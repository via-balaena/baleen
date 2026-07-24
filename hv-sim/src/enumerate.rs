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
//! **Saturation (Tier B).** For a config whose state carries no *unbounded* field, the
//! reachable set is finite even without a depth bound, so the BFS frontier eventually goes
//! *empty* — [`EnumOutcome::saturated`] — and the theorem strengthens to *all* depths, not
//! just `<= depth`. The one unbounded field is a refcount (`grant::maps`, a frame's `refs`),
//! which grows only when a grant maps an *owned* frame — i.e. `grant` and `p2m` enabled
//! together. Every other config saturates; grant+p2m alone is infinite and finite only per
//! depth. See `docs/TIER-B-CUTOFF.md` for the full cutoff / small-scope-completeness argument.
//!
//! **Focus by seam.** Enabling every op group at once explodes the branching factor, so
//! [`Config`] selects which subsystems' hypercalls to enumerate. Running grant+p2m
//! together exhaustively covers the grant↔page-type and page-table↔grant seams;
//! evtchn+sched covers the lost-wakeup seam — each at a far larger depth than the full
//! cross-product would allow. Credit is orthogonal (it touches nothing else) and left
//! out.
//!
//! Not `no_std`: this is host-only harness code, like the rest of `hv-sim`.

use std::collections::{HashMap, HashSet};

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
    /// Symmetry reduction: dedup on the **canonical** state key (the orbit
    /// representative under id-permutation) instead of the raw [`state_key`]. Sound
    /// because the core is data-independent — no transition or invariant branches on a
    /// literal id (see `docs/TIER-B-CUTOFF.md` §2.1) — so permuting frames / ports /
    /// grants maps a reachable state to a behaviourally identical reachable state.
    /// Collapses each symmetry orbit to one state, shrinking the reachable set by up to
    /// the group order, which can turn an argued-finite config into a *measured* saturated
    /// one. Off by default: every existing sweep runs unreduced (the ground truth the
    /// reduction is validated against). See `canonical_key`.
    pub symmetry: bool,
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
            symmetry: false,
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
    /// True iff the search closed by **saturation** — a BFS frontier that went *empty*
    /// before the depth budget ran out, meaning every state reachable in the config was
    /// visited *at every depth*, not merely up to `cfg.depth`. This is the Tier-B
    /// distinction: a saturated run is an **all-depths theorem** for that fixed config (the
    /// entire reachable state space is finite and fully explored — see [`enumerate`]),
    /// whereas a merely non-truncated run that exhausted its depth budget is complete only
    /// *up to* `cfg.depth`. Never true when `truncated` is (a capped run cannot prove the
    /// frontier empty). The finiteness that makes saturation reachable at all rests on
    /// [`state_key`] carrying no unbounded field: every fingerprint component ranges over a
    /// set bounded by the config's fixed sizes, so the distinct-state set is finite and BFS
    /// must eventually empty its frontier at *some* depth.
    pub saturated: bool,
    /// A shortest counterexample: the hypercall path from `new()` to a state that
    /// violates the integrated invariant, or `None` if none exists within `depth`.
    pub violation: Option<Vec<(u16, HvCall)>>,
    /// If the counterexample is a **Stage-2 refinement** failure rather than (or as well as) a
    /// model-invariant failure, the specific way the emitted page table betrayed the model. `None`
    /// when the run was clean, or when the counterexample was a pure `invariants_hold` violation.
    ///
    /// This is the metal's half of the check: `invariants_hold` asks "is the *model* consistent?",
    /// [`hv_s2::check_all`] asks "does the page table we would *emit* from this model authorize
    /// exactly what the model permits?" — over the same reachable states.
    pub refinement: Option<hv_s2::Violation>,
    /// How many distinct reachable states fell **outside** the Stage-2 refinement's domain
    /// ([`hv_s2::OutOfDomain`]) — a frame that is a leaf at two spans, or a leaf level the
    /// refinement does not emit.
    ///
    /// **Not violations.** This is the refinement's *coverage*, measured rather than asserted: a
    /// nonzero count says the model routinely reaches states the emitted table cannot faithfully
    /// represent, which the metal must (and does) fail loudly on. Surfaced because the alternative
    /// — discarding it — is how a scope limit turns into an unstated assumption.
    pub out_of_domain: usize,
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
///
/// `pub(crate)` so the Tier-D non-interference bridge ([`crate::noninterference`])
/// drives the *same* transition universe the reachability sweep does — the check must
/// quantify over exactly the transitions the enumerator proves the invariants over, or
/// it would be testing a different machine.
pub(crate) fn ops(cfg: &Config) -> Vec<(u16, HvCall)> {
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
                // Every affinity mask over the pCPU set, for every `target` — so the
                // model-checker drives the full spectrum from empty (unschedulable) through
                // single-pCPU pins to the all-pCPUs default (exercising the run guard and the
                // set-affinity guard at every placement), *and* every authority path: a
                // self-affinity op (`caller == target`), an authorized peer op (a controller
                // over `target`), and a `Denied` peer op (no control). Driving `target` is
                // mandatory now that it is an explicit field (design-lesson #14f).
                for target in 0..doms {
                    for affinity in 0..(1u64 << cfg.pcpus) {
                        v.push((
                            caller,
                            HvCall::SchedSetAffinity {
                                target,
                                vcpu,
                                affinity,
                            },
                        ));
                    }
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

/// A grant table entry: `(grantee, frame, readonly, maps, writable_maps)`.
type GrantEntry = (u16, u32, bool, u32, u32);
/// A live grant mapping at a handle: `(grantee, grantor, gref, writable)`.
type Mapping = (u16, u16, u32, bool);
/// A page-table edge: `(parent, slot, child, writable, leaf)`.
type Edge = (u32, u32, u32, bool, bool);

/// A plain-data extract of exactly the observable state that [`snapshot_key`]
/// fingerprints — the read-once form of a [`Hypervisor`] that [`permute`] can relabel
/// without touching `hv-core`. Symmetry reduction needs to apply an id-permutation and
/// re-fingerprint; permuting a live `Hypervisor` would need core mutators, so instead we
/// read the state out once into this struct and permute the copy. Per-domain arrays are
/// row-major (`dom * stride + local`).
#[derive(Clone)]
struct Snapshot {
    n_dom: usize,
    n_port: usize,
    n_grant: usize,
    n_vcpu: usize,
    n_pcpu: usize,
    n_frame: usize,
    /// Per `(dom, port)`. `PortState` carries its own `remote` / `remote_port` / `vcpu`.
    ports: Vec<PortRec>,
    /// Per `(dom, gref)`.
    grants: Vec<Option<GrantEntry>>,
    /// Per handle slot (a global pool).
    mappings: Vec<Option<Mapping>>,
    /// Per `(dom, vcpu)`.
    vcpus: Vec<VcpuRec>,
    /// Per pCPU: the `(dom, vcpu)` occupying it, if any.
    occ: Vec<Option<(u16, u32)>>,
    /// Per mfn.
    frames: Vec<Option<FrameRec>>,
    /// A page-table edge set — unordered (sorted in the key).
    edges: Vec<Edge>,
    live: Vec<bool>,
    may_create: Vec<bool>,
    /// Per `(holder, target)`.
    control: Vec<Control>,
}

#[derive(Clone, Copy)]
struct PortRec {
    state: PortState,
    pending: bool,
    masked: bool,
}

#[derive(Clone, Copy)]
struct VcpuRec {
    state: RunState,
    affinity: u64,
}

#[derive(Clone, Copy)]
struct FrameRec {
    owner: u16,
    refs: u32,
    writable_refs: u32,
    pagetable_refs: u32,
    ty: Option<PageType>,
    pinned: bool,
}

impl Snapshot {
    /// Read the whole observable state out of a `Hypervisor` — the exact set of fields
    /// [`state_key`] fingerprints, and nothing more. Sizes are uniform across domains
    /// (every domain is created with the same universe), so domain 0's counts stand for all.
    fn from_hv(hv: &Hypervisor) -> Snapshot {
        let e = hv.evtchn();
        let g = hv.grant();
        let s = hv.sched();
        let p = hv.p2m();
        let n_dom = hv.domain_count();
        let n_port = if n_dom > 0 { e.port_count(0) } else { 0 };
        let n_grant = if n_dom > 0 { g.entry_count(0) } else { 0 };
        let n_vcpu = if n_dom > 0 { s.vcpu_count(0) } else { 0 };
        let n_pcpu = s.pcpu_count();
        let n_frame = p.frame_count();

        let mut ports = Vec::with_capacity(n_dom * n_port);
        for dom in 0..n_dom as u16 {
            for port in 0..n_port as u32 {
                ports.push(PortRec {
                    state: e.state_of(dom, port).unwrap_or(PortState::Free),
                    pending: e.is_pending(dom, port),
                    masked: e.is_masked(dom, port),
                });
            }
        }

        let mut grants = Vec::with_capacity(n_dom * n_grant);
        for dom in 0..n_dom as u16 {
            for gref in 0..n_grant as u32 {
                grants.push(g.grant_entry(dom, gref));
            }
        }
        let mappings = (0..g.handle_slots() as u32)
            .map(|h| g.mapping_at(h))
            .collect();

        let mut vcpus = Vec::with_capacity(n_dom * n_vcpu);
        for dom in 0..n_dom as u16 {
            for vcpu in 0..n_vcpu as u32 {
                vcpus.push(VcpuRec {
                    state: s.state_of(dom, vcpu).unwrap_or(RunState::Offline),
                    affinity: s.affinity_of(dom, vcpu).unwrap_or(0),
                });
            }
        }
        let occ = (0..n_pcpu as u32).map(|pcpu| s.occupant(pcpu)).collect();

        let mut frames = Vec::with_capacity(n_frame);
        for mfn in 0..n_frame as u32 {
            frames.push(p.owner_of(mfn).map(|owner| {
                let ty = p.current_type(mfn);
                let pagetable_refs = match ty {
                    Some(pt @ PageType::PageTable(_)) => p.type_refs(mfn, pt).unwrap_or(0),
                    _ => 0,
                };
                FrameRec {
                    owner,
                    refs: p.refs(mfn).unwrap_or(0),
                    writable_refs: p.type_refs(mfn, PageType::Writable).unwrap_or(0),
                    pagetable_refs,
                    ty,
                    pinned: p.is_pinned(mfn),
                }
            }));
        }
        let edges = p.link_edges();

        let live = (0..n_dom as u16).map(|d| hv.is_live(d)).collect();
        let may_create = (0..n_dom as u16).map(|d| hv.may_create(d)).collect();
        let mut control = Vec::with_capacity(n_dom * n_dom);
        for holder in 0..n_dom as u16 {
            for target in 0..n_dom as u16 {
                control.push(hv.control_edge(holder, target));
            }
        }

        Snapshot {
            n_dom,
            n_port,
            n_grant,
            n_vcpu,
            n_pcpu,
            n_frame,
            ports,
            grants,
            mappings,
            vcpus,
            occ,
            frames,
            edges,
            live,
            may_create,
            control,
        }
    }
}

/// The canonical fingerprint of a [`Snapshot`]. Two snapshots share a key iff they are
/// behaviourally identical, so BFS deduplication on it neither merges distinct states
/// (which would drop coverage) nor splits equivalent ones needlessly. It keeps every field
/// a future transition can read and drops the ones none can — a vCPU's accrued
/// `runtime`/`dispatched_at` (gate nothing) and a frame's `pt_level` while it is untyped
/// (dead). Grant *handle* identity is kept (unmap targets a handle); page-table edges are
/// keyed by `(parent, slot)`, so their *set* — sorted here — is canonical.
///
/// This is the single source of truth for the fingerprint layout: [`state_key`] is a thin
/// wrapper over `snapshot_key(&Snapshot::from_hv(hv))`, and the symmetry-reduced
/// [`canonical_key`] minimises `snapshot_key` over the permutation group.
fn snapshot_key(sn: &Snapshot) -> Vec<u64> {
    let mut k = Vec::new();

    for dom in 0..sn.n_dom {
        for port in 0..sn.n_port {
            let r = &sn.ports[dom * sn.n_port + port];
            let (tag, a, b) = match r.state {
                PortState::Free => (0, 0, 0),
                PortState::Unbound { remote } => (1, u64::from(remote), 0),
                PortState::Interdomain {
                    remote,
                    remote_port,
                } => (2, u64::from(remote), u64::from(remote_port)),
                PortState::Virq { vcpu, virq } => (3, u64::from(vcpu), u64::from(virq)),
                PortState::Ipi { vcpu } => (4, u64::from(vcpu), 0),
            };
            k.extend([tag, a, b, r.pending as u64, r.masked as u64]);
        }
    }
    k.push(0xFFFF_0001);

    for dom in 0..sn.n_dom {
        for gref in 0..sn.n_grant {
            match sn.grants[dom * sn.n_grant + gref] {
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
    let live = (0..sn.mappings.len())
        .rev()
        .find(|&h| sn.mappings[h].is_some())
        .map(|h| h + 1)
        .unwrap_or(0);
    for h in 0..live {
        match sn.mappings[h] {
            Some((ge, gr, gref, w)) => {
                k.extend([1, u64::from(ge), u64::from(gr), u64::from(gref), w as u64])
            }
            None => k.extend([0, 0, 0, 0, 0]),
        }
    }
    k.push(0xFFFF_0002);

    for dom in 0..sn.n_dom {
        for vcpu in 0..sn.n_vcpu {
            let vr = &sn.vcpus[dom * sn.n_vcpu + vcpu];
            // Run state only — runtime and dispatched_at gate no transition.
            let (tag, p) = match vr.state {
                RunState::Offline => (0, 0),
                RunState::Runnable => (1, 0),
                RunState::Running { pcpu } => (2, u64::from(pcpu)),
                RunState::Blocked => (3, 0),
            };
            // The affinity mask IS behaviourally live — it gates which pCPU `run` may target
            // — so two states differing only in a vCPU's affinity are distinct and must not
            // merge (design-lesson #7). Contrast `runtime`/`dispatched_at`, dropped above
            // because no transition reads them. (An Offline vCPU always carries the default
            // mask, so this adds no spurious states for offline vCPUs.)
            k.extend([tag, p, vr.affinity]);
        }
    }
    for pcpu in 0..sn.n_pcpu {
        match sn.occ[pcpu] {
            Some((d, v)) => k.extend([1, u64::from(d), u64::from(v)]),
            None => k.extend([0, 0, 0]),
        }
    }
    k.push(0xFFFF_0003);

    for mfn in 0..sn.n_frame {
        match sn.frames[mfn] {
            Some(f) => k.extend([
                1,
                u64::from(f.owner),
                u64::from(f.refs),
                u64::from(f.writable_refs),
                u64::from(f.pagetable_refs),
                level_tag(f.ty),
                f.pinned as u64,
            ]),
            None => k.extend([0, 0, 0, 0, 0, 0, 0]),
        }
    }
    let mut edges = sn.edges.clone();
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
    for dom in 0..sn.n_dom {
        k.push(sn.live[dom] as u64);
        k.push(sn.may_create[dom] as u64);
    }
    // Fingerprint each control edge's *provenance*, not just its presence: two states
    // differing only in who delegated an edge are behaviourally distinct — they permit
    // different chain-restricted revokes (an ancestor may prune where a non-ancestor is
    // Denied) — so keying presence alone would wrongly merge them and drop coverage
    // (design-lesson #7). Absent=0, Root=1, Via(d)=2+d, an injective tag per cell value.
    for holder in 0..sn.n_dom {
        for target in 0..sn.n_dom {
            let tag = match sn.control[holder * sn.n_dom + target] {
                Control::Absent => 0,
                Control::Root => 1,
                Control::Via(d) => 2 + u64::from(d),
            };
            k.push(tag);
        }
    }

    k
}

/// A canonical fingerprint of the whole integrated state (see `snapshot_key`).
pub fn state_key(hv: &Hypervisor) -> Vec<u64> {
    snapshot_key(&Snapshot::from_hv(hv))
}

// ─── symmetry reduction ──────────────────────────────────────────────────────────
//
// The core is *data-independent*: no transition and no invariant branches on the literal
// value of any id (`docs/TIER-B-CUTOFF.md` §2.1), so permuting the ids of one entity kind
// carries a reachable state to a behaviourally identical reachable state. Deduplicating on
// the orbit representative — the lexicographically minimal `snapshot_key` over the
// permutation group — therefore collapses each orbit to one state without ever merging two
// genuinely distinct states. That is sound *only* if every permutation we apply is a real
// symmetry and every cross-reference is remapped consistently, which is exactly what the
// `symmetry_group_*` validation tests pin down.
//
// Two distinguished ids the code is NOT symmetric under, so we leave them fixed: domain 0
// (boots Live with `may_create` — the sole boot asymmetry) and vCPU 0 (an Interdomain /
// Unbound port's `notify_target` is hardcoded to vCPU 0 — `evtchn.rs`, an asymmetry §2.1
// missed). With ≤ 2 vCPUs and ≤ 2 pCPUs in every config the vCPU/pCPU stabilizers are
// trivial anyway, and domain permutation is deferred (it couples the per-domain arrays);
// Phase 1 permutes the three id kinds the code compares purely structurally and that carry
// the payoff: frames (global), and ports and grants (each domain independently).

/// One symmetry-group element. `frame[m]` is the new id of old frame `m`; `port[d]` and
/// `grant[d]` are old-domain `d`'s local port / grant permutations (each a bijection of
/// `0..count`). Domains, vCPUs and pCPUs are held fixed (see the module note above).
struct Perm {
    frame: Vec<usize>,
    port: Vec<Vec<usize>>,
    grant: Vec<Vec<usize>>,
}

/// Apply a permutation to a snapshot, remapping every id-bearing field *and* every
/// cross-reference. Getting the cross-references complete is the whole soundness burden:
/// a port's `remote_port` indexes the *remote* domain's port table (remapped by that
/// domain's port perm), a grant mapping's `gref` indexes the *grantor's* grant table
/// (remapped by the grantor's grant perm), and an edge's parent/child are frame ids. A
/// missed remap would forge a state that is not actually symmetric and silently merge
/// distinct states — hence the exhaustive `symmetry_group_is_a_reachability_automorphism`
/// closure check.
fn permute(sn: &Snapshot, g: &Perm) -> Snapshot {
    let (nd, np, ng) = (sn.n_dom, sn.n_port, sn.n_grant);

    // Ports: move `(dom, p)` to `(dom, port[dom][p])`; remap an Interdomain peer's
    // `remote_port` by the *remote* domain's port permutation.
    let mut ports = sn.ports.clone();
    for dom in 0..nd {
        for p in 0..np {
            let mut rec = sn.ports[dom * np + p];
            if let PortState::Interdomain {
                remote,
                remote_port,
            } = rec.state
            {
                let rp = g.port[remote as usize][remote_port as usize] as u32;
                rec.state = PortState::Interdomain {
                    remote,
                    remote_port: rp,
                };
            }
            ports[dom * np + g.port[dom][p]] = rec;
        }
    }

    // Grant entries: move `(dom, j)` to `(dom, grant[dom][j])`; remap the granted frame id.
    let mut grants = sn.grants.clone();
    for dom in 0..nd {
        for j in 0..ng {
            let e = sn.grants[dom * ng + j]
                .map(|(ge, fr, ro, m, wm)| (ge, g.frame[fr as usize] as u32, ro, m, wm));
            grants[dom * ng + g.grant[dom][j]] = e;
        }
    }

    // Grant mappings: `gref` indexes the grantor's entry table — remap by the grantor's
    // grant perm. Handle position is unchanged (handles are not permuted).
    let mappings = sn
        .mappings
        .iter()
        .map(|m| m.map(|(ge, gr, gref, w)| (ge, gr, g.grant[gr as usize][gref as usize] as u32, w)))
        .collect();

    // Frames: relabel each frame's id (its record's contents are unchanged — the owner is a
    // domain, and domains are fixed in Phase 1).
    let mut frames = vec![None; sn.n_frame];
    for m in 0..sn.n_frame {
        frames[g.frame[m]] = sn.frames[m];
    }

    // Edges: remap parent and child frame ids; slot / writable / leaf are unchanged.
    let edges = sn
        .edges
        .iter()
        .map(|&(par, slot, ch, w, leaf)| {
            (
                g.frame[par as usize] as u32,
                slot,
                g.frame[ch as usize] as u32,
                w,
                leaf,
            )
        })
        .collect();

    Snapshot {
        n_dom: nd,
        n_port: np,
        n_grant: ng,
        n_vcpu: sn.n_vcpu,
        n_pcpu: sn.n_pcpu,
        n_frame: sn.n_frame,
        ports,
        grants,
        mappings,
        // vCPUs, pCPU occupancy, lifecycle and control are all keyed by fixed ids in Phase 1.
        vcpus: sn.vcpus.clone(),
        occ: sn.occ.clone(),
        frames,
        edges,
        live: sn.live.clone(),
        may_create: sn.may_create.clone(),
        control: sn.control.clone(),
    }
}

/// Every permutation of `0..k` (row 0 is the identity `0,1,…`).
fn perms_of(k: usize) -> Vec<Vec<usize>> {
    fn rec(cur: &mut Vec<usize>, i: usize, out: &mut Vec<Vec<usize>>) {
        if i == cur.len() {
            out.push(cur.clone());
            return;
        }
        for j in i..cur.len() {
            cur.swap(i, j);
            rec(cur, i + 1, out);
            cur.swap(i, j);
        }
    }
    let mut cur: Vec<usize> = (0..k).collect();
    let mut out = Vec::new();
    rec(&mut cur, 0, &mut out);
    out
}

/// Every `d`-length tuple whose entries are each drawn from `base` — the independent
/// per-domain choice of a port (or grant) permutation.
fn cartesian_power(base: &[Vec<usize>], d: usize) -> Vec<Vec<Vec<usize>>> {
    let mut acc: Vec<Vec<Vec<usize>>> = vec![vec![]];
    for _ in 0..d {
        acc = acc
            .iter()
            .flat_map(|prefix| {
                base.iter().map(move |b| {
                    let mut t = prefix.clone();
                    t.push(b.clone());
                    t
                })
            })
            .collect();
    }
    acc
}

/// Build the symmetry group for a config. A permutation kind is included only when it is
/// non-trivial *and* the subsystem that gives its ids meaning is enabled — a pure
/// performance gate (a symmetry that acts as the identity on the reachable states just
/// wastes `snapshot_key` calls). Every factor's first element is the identity, so the group
/// always contains the identity and `canonical_key` is well-defined. Omitting any factor is
/// always sound (a subgroup reduces less, never wrongly).
fn group(cfg: &Config) -> Vec<Perm> {
    let d = cfg.domains;
    let frame_sym = cfg.frames >= 2 && (cfg.p2m || cfg.grant);
    let port_sym = cfg.ports >= 2 && cfg.evtchn;
    let grant_sym = cfg.grants >= 2 && cfg.grant;

    let id_frame: Vec<usize> = (0..cfg.frames).collect();
    let id_port: Vec<usize> = (0..cfg.ports).collect();
    let id_grant: Vec<usize> = (0..cfg.grants).collect();

    let frame_perms = if frame_sym {
        perms_of(cfg.frames)
    } else {
        vec![id_frame]
    };
    let port_tuples = if port_sym {
        cartesian_power(&perms_of(cfg.ports), d)
    } else {
        vec![vec![id_port; d]]
    };
    let grant_tuples = if grant_sym {
        cartesian_power(&perms_of(cfg.grants), d)
    } else {
        vec![vec![id_grant; d]]
    };

    let mut out = Vec::new();
    for f in &frame_perms {
        for pt in &port_tuples {
            for gt in &grant_tuples {
                out.push(Perm {
                    frame: f.clone(),
                    port: pt.clone(),
                    grant: gt.clone(),
                });
            }
        }
    }
    out
}

/// The orbit representative: the lexicographically minimal `snapshot_key` over the group.
/// Constant on each symmetry orbit (it is a min over the whole group) and — because
/// `snapshot_key` separates distinct states and every `g` is a genuine symmetry —
/// different on different orbits. So deduplicating BFS on it is sound.
fn canonical_key(sn: &Snapshot, grp: &[Perm]) -> Vec<u64> {
    grp.iter()
        .map(|g| snapshot_key(&permute(sn, g)))
        .min()
        .expect("group always contains the identity")
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

    // With symmetry reduction, dedup on the orbit representative (the canonical key over the
    // permutation group), so all symmetric variants of a state collapse to one; otherwise
    // dedup on the raw state key. The group is built once and reused. Invariant checking is
    // always done on the *concrete* state before keying, so reduction can never hide a
    // violation — it only decides whether a state is re-expanded.
    let grp = cfg.symmetry.then(|| group(cfg));
    let keyfn = |hv: &Hypervisor| -> StateKey {
        match &grp {
            Some(g) => canonical_key(&Snapshot::from_hv(hv), g),
            None => state_key(hv),
        }
    };

    // Each visited state records how it was first reached, for counterexample traces.
    // The root maps to itself with no op.
    let mut came_from: CameFrom = HashMap::new();
    let mut frontier: Vec<(StateKey, Hypervisor)> = Vec::new();
    let root_key = keyfn(&init);
    came_from.insert(root_key.clone(), None);
    frontier.push((root_key, init));
    let mut truncated = false;
    // How many reachable states fell OUTSIDE the Stage-2 refinement's domain (see
    // `hv_s2::OutOfDomain`). Not violations — a measurement of how much of the reachable set the
    // refinement actually claims.
    // Distinct STATES that fell outside the refinement's domain — a set, not a counter. The check
    // runs once per generated transition, and states are deduped afterwards, so a naive counter
    // measures checks and can exceed the state count outright (it reported 908% before this was
    // fixed). A coverage figure has to be states-over-states or it is not a fraction of anything.
    let mut out_of_domain_keys: HashSet<Vec<u64>> = HashSet::new();
    // Set once the frontier goes empty *without* truncation — the config's whole reachable
    // set is exhausted at every depth (an all-depths theorem). A run that instead exhausts
    // its depth budget leaves this false: it is complete only up to `cfg.depth`.
    let mut saturated = false;

    for _ in 0..cfg.depth {
        let mut next: Vec<(StateKey, Hypervisor)> = Vec::new();
        for (_, hv) in &frontier {
            for &(caller, call) in &universe {
                let mut h = hv.clone();
                let _: Result<HvOutcome, _> = h.dispatch(caller, call);
                // Two predicates at every reachable state: hv-core's own invariants, and the
                // Stage-2 REFINEMENT — that the page table emitted from this state authorizes
                // exactly what the model permits (no reachability without ownership or a grant).
                // The second is what turns Architecture Audit #2's three hand-written mutations
                // into a property checked over the whole reachable set.
                // A refinement VERDICT is not automatically a counterexample: `OutOfDomain` says
                // the model reached a state the refinement does not claim to cover (one frame at two
                // spans; a leaf level we do not emit), which is a COVERAGE fact, not a defect. Only
                // `Violated` is a finding. Counting the rest is how the refinement's domain becomes a
                // measured number instead of a sentence in a doc.
                let refinement = match hv_s2::check_all(&h) {
                    Ok(()) => None,
                    Err(hv_s2::Verdict::Violated(v)) => Some(v),
                    Err(hv_s2::Verdict::OutOfDomain(_)) => {
                        out_of_domain_keys.insert(keyfn(&h));
                        None
                    }
                };
                if !h.invariants_hold() || refinement.is_some() {
                    let key = keyfn(&h);
                    came_from.insert(key.clone(), Some((keyfn(hv), caller, call)));
                    return EnumOutcome {
                        states: came_from.len(),
                        truncated,
                        saturated: false,
                        violation: Some(trace(&came_from, &key)),
                        refinement,
                        out_of_domain: out_of_domain_keys.len(),
                    };
                }
                let key = keyfn(&h);
                if !came_from.contains_key(&key) {
                    if came_from.len() >= cfg.max_states {
                        truncated = true;
                        continue;
                    }
                    came_from.insert(key.clone(), Some((keyfn(hv), caller, call)));
                    next.push((key, h));
                }
            }
        }
        if next.is_empty() {
            // The frontier emptied. If no state was ever dropped to the cap, this is genuine
            // saturation — no unvisited state remains at *any* depth. If we did truncate, the
            // empty frontier is an artefact of the cap, not a proof, so we must not claim it.
            saturated = !truncated;
            break;
        }
        frontier = next;
    }

    EnumOutcome {
        states: came_from.len(),
        truncated,
        saturated,
        violation: None,
        refinement: None,
        out_of_domain: out_of_domain_keys.len(),
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
            "violated after: {:?}{}",
            out.violation.as_ref().unwrap(),
            // Name WHICH predicate failed: a bare trace cannot distinguish a model-invariant
            // break from a Stage-2 refinement break, and they have very different diagnoses.
            match &out.refinement {
                Some(v) => format!(" [Stage-2 REFINEMENT: {v:?}]"),
                None => " [hv-core invariant]".to_string(),
            }
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
    // point — so truncation is tolerated (and reported). Reports whether the run merely
    // completed to depth, or *saturated* (frontier went empty → an all-depths theorem for
    // the config, the Tier-B distinction).
    fn expect_no_violation(cfg: &Config) -> EnumOutcome {
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
                " (hit the state cap — a lower bound)".to_string()
            } else if out.saturated {
                format!(
                    " (SATURATED at depth <= {} — the config's ENTIRE reachable set, all depths)",
                    cfg.depth
                )
            } else {
                " (closed for this depth — complete up to cfg.depth, frontier still non-empty)"
                    .to_string()
            }
        );
        out
    }

    // For a config small enough to fully saturate: assert the search closed by an *empty
    // frontier*, not by exhausting its depth budget. This upgrades the result from "safe up
    // to depth D" to "safe at every depth — the config's whole finite reachable set is
    // proven clean" (Tier B: the depth bound dissolves for this fixed size).
    fn expect_saturated(cfg: &Config) -> usize {
        let out = enumerate(cfg);
        assert!(
            out.violation.is_none(),
            "invariant violated after: {:?}",
            out.violation.unwrap()
        );
        assert!(
            !out.truncated,
            "hit the {}-state cap before saturating — raise max_states or shrink the config",
            cfg.max_states
        );
        assert!(
            out.saturated,
            "did not saturate at depth {}: {} states explored with a non-empty frontier — \
             raise depth until the frontier empties",
            cfg.depth, out.states
        );
        out.states
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
    /// vCPU affinity in focus: the scheduler over **two pCPUs** (so a mask can genuinely
    /// exclude a pCPU — with one pCPU affinity is trivial), driving `SchedSetAffinity` across
    /// every mask alongside admit/run/preempt/block/wake/offline and create/destroy. Every
    /// reachable interleaving is proven to keep a `Running` vCPU on a pCPU its mask permits
    /// (`RunningOffAffinity`) *and* pCPU exclusivity — the scheduler's two safety invariants
    /// together, over the full space of pins (empty, single-pCPU, all-pCPUs) and placements.
    /// Create/destroy so the offline affinity-reset (a reborn vCPU starts at the default) is
    /// covered too.
    fn affinity_cfg(depth: u32) -> Config {
        Config {
            sched: true,
            create: true,
            destroy: true,
            vcpus: 2,
            pcpus: 2,
            depth,
            ..Config::tiny()
        }
    }

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

    /// vCPU affinity crossed with the **whole** integrated core, over **two pCPUs**. `all_cfg`
    /// runs one pCPU, where affinity is trivial (the mask can exclude nothing), so affinity has
    /// only ever been model-checked *in isolation* (`affinity_cfg`) — its orthogonality to the
    /// grant / page-type / event seams was *argued* (no cross-invariant reads the affinity mask,
    /// and no non-scheduler transition touches scheduler state), never *checked together*. This
    /// config turns that argument into a proof over the shared reachable state: every subsystem
    /// on, two vCPUs over two pCPUs so a mask genuinely excludes a pCPU, plus create/destroy/
    /// delegate — so if any coupling between affinity and the other seams existed, a
    /// `RunningOffAffinity` (or any other) breach would surface in the *combined* interleaving.
    /// (None does; this is the empirical half of the audit's decomposition argument — Tier A of
    /// the true-diamond program.)
    fn all_affinity_cfg(depth: u32) -> Config {
        Config {
            evtchn: true,
            grant: true,
            sched: true,
            p2m: true,
            create: true,
            destroy: true,
            delegate: true,
            vcpus: 2,
            pcpus: 2,
            depth,
            ..Config::tiny()
        }
    }

    /// Tier A larger-scope: the grant / page-type seams over **three** domains and **three**
    /// frames, not two. The small-scope hypothesis is the load-bearing assumption behind every
    /// bounded sweep — this probes it directly by adding a third party, so a bug that only
    /// manifests with three domains sharing (A grants to B while C owns/maps something) would
    /// surface where the two-domain `grant_p2m_cfg` cannot even represent it.
    fn grant_p2m_3dom_cfg(depth: u32) -> Config {
        Config {
            grant: true,
            p2m: true,
            create: true,
            destroy: true,
            domains: 3,
            frames: 3,
            depth,
            ..Config::tiny()
        }
    }

    /// Tier A cross: **delegated** control (`Via` edges) together with grant + interdomain
    /// event channels over three domains. The audit *argued* a `Via` edge drives the identical
    /// grant/evtchn teardown a creation `Root` edge does (the cascade touches only the control
    /// matrix), so delegate × grant × evtchn is decomposable — but it was never checked together:
    /// `reuse_cfg` has grant+evtchn but no delegate, `delegation_cfg` has delegate but no
    /// grant/evtchn. Three domains is the smallest world that forms a `Via` edge *and* a
    /// cross-domain reference, so this turns that argument into a check.
    fn authority_seams_cfg(depth: u32) -> Config {
        Config {
            evtchn: true,
            grant: true,
            create: true,
            destroy: true,
            delegate: true,
            domains: 3,
            depth,
            ..Config::tiny()
        }
    }

    /// Tier A completeness: the page-table hierarchy over **all four** levels (`L1..L4`) with
    /// enough frames to stack a deep tree, not just the `L1`/`L2` the other configs use. The
    /// level logic is level-generic (`interior_child_type`, the `get_type` level-conflict), so
    /// `L3`/`L4` are isomorphic to `L1`/`L2` by inspection — this closes the gap empirically
    /// anyway, proving the higher levels' typing and interior-child discipline over a real sweep.
    fn deep_hierarchy_cfg(depth: u32) -> Config {
        Config {
            p2m: true,
            create: true,
            destroy: true,
            levels: vec![PtLevel::L1, PtLevel::L2, PtLevel::L3, PtLevel::L4],
            frames: 4,
            depth,
            ..Config::tiny()
        }
    }

    // ─── Tier A: larger-scope + cross-invariant + full-hierarchy sweeps ──────────────
    // Each has a CI-shallow test (closes fast in debug) and a deep `#[ignore]`d twin that
    // closes to a theorem in release. Together they close the bounded gaps the audit left:
    // three-domain scope (the small-scope hypothesis at K+1), the delegate × grant × evtchn
    // cross (argued decomposable, now checked), and the L3/L4 levels (isomorphic to L1/L2).

    #[test]
    fn grant_p2m_over_three_domains_is_sound() {
        let states = expect_clean(&grant_p2m_3dom_cfg(3));
        assert!(states > 200, "suspiciously few states explored: {states}");
    }

    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn grant_p2m_over_three_domains_deep() {
        let mut cfg = grant_p2m_3dom_cfg(5);
        cfg.max_states = 4_000_000;
        expect_no_violation(&cfg); // closes ≈1.82M states
    }

    #[test]
    fn delegation_crossed_with_grant_and_evtchn_is_sound() {
        let states = expect_clean(&authority_seams_cfg(3));
        assert!(states > 200, "suspiciously few states explored: {states}");
    }

    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn delegation_crossed_with_grant_and_evtchn_deep() {
        let mut cfg = authority_seams_cfg(5);
        cfg.max_states = 4_000_000;
        expect_no_violation(&cfg); // closes ≈1.27M states
    }

    #[test]
    fn the_four_level_hierarchy_is_sound() {
        let states = expect_clean(&deep_hierarchy_cfg(5));
        assert!(states > 200, "suspiciously few states explored: {states}");
    }

    /// **M5 Arc 6a — the refinement's DOMAIN, measured.** The span-aware refinement declines to
    /// emit two classes of legal model state (one frame that is a leaf at two spans; a leaf level
    /// the emitter does not encode). Those are not violations — the metal halts loudly on them —
    /// but "how much of the reachable set does the refinement actually cover?" must be a NUMBER,
    /// not a sentence, or a scope limit quietly becomes an unstated assumption.
    ///
    /// This config reaches both classes within a handful of hypercalls, so a zero here would mean
    /// the counter stopped working, not that the domain grew.
    #[test]
    fn refinement_domain_coverage_is_measured() {
        let out = enumerate(&deep_hierarchy_cfg(5));
        assert!(
            out.violation.is_none(),
            "a real refinement violation, not a domain limit: {:?}",
            out.refinement
        );
        assert!(
            out.out_of_domain > 0,
            "this config is known to reach out-of-domain states; a zero means the counter broke"
        );
        println!(
            "refinement domain: {} of {} reachable states are OUT OF DOMAIN ({:.1}%)",
            out.out_of_domain,
            out.states,
            100.0 * out.out_of_domain as f64 / out.states as f64
        );
    }

    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn the_four_level_hierarchy_deep() {
        let mut cfg = deep_hierarchy_cfg(8);
        cfg.max_states = 4_000_000;
        expect_no_violation(&cfg);
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

    /// vCPU affinity crossed with the *whole* core over two pCPUs, shallow: the combined
    /// interleaving the isolated `affinity_cfg` (affinity only) and the one-pCPU `all_cfg`
    /// (affinity trivial) never exercised together. Closes the audit's "affinity is orthogonal"
    /// *argument* into a *checked* result — Tier A of the true-diamond program. The deep twin
    /// runs far enough to have a vCPU `Running` on an affinity-restricted pCPU while grants and
    /// page tables are live across both domains.
    #[test]
    fn affinity_crossed_with_the_full_core_is_sound() {
        let states = expect_clean(&all_affinity_cfg(3));
        assert!(states > 200, "suspiciously few states explored: {states}");
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

    /// vCPU affinity, exhaustively (shallow): every reachable interleaving of set-affinity,
    /// dispatch, and the run-state transitions over two pCPUs keeps every `Running` vCPU on a
    /// pCPU its hard-affinity mask permits — a proof of `RunningOffAffinity` (and pCPU
    /// exclusivity) across the full mask space. The deep twin runs far enough to pin, dispatch,
    /// contend, and reset affinity through offline/rebirth.
    #[test]
    fn vcpu_affinity_is_exhaustively_sound() {
        let states = expect_clean(&affinity_cfg(4));
        assert!(states > 200, "suspiciously few states explored: {states}");
    }

    /// vCPU affinity, **saturated to an all-depths theorem**. The scheduler carries no
    /// unbounded refcount (run states, masks, and occupancy are all bounded by the config
    /// sizes — `runtime` is excluded from `state_key`), so its reachable set is finite and
    /// BFS empties the frontier: at depth 16 the sweep does not merely finish its budget, it
    /// *saturates* (237,312 states), proving `RunningOffAffinity` + pCPU exclusivity hold in
    /// **every** reachable state of this config at **every** depth — the depth bound has
    /// dissolved. See `docs/TIER-B-CUTOFF.md` §1. (`affinity_cfg` uses `Config::tiny`'s
    /// 1.5M cap, far above 237k, so it closes by an empty frontier, not the cap.)
    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn vcpu_affinity_deep() {
        let states = expect_saturated(&affinity_cfg(16));
        assert!(
            states > 200_000,
            "affinity reachable set unexpectedly small: {states}"
        );
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

    /// The deep domain-ID-reuse sweep, **closed to a theorem**. Depth 7 is enough to bring up a
    /// slot, grant it a frame (or open an interdomain channel to it), destroy it, and recreate it,
    /// and — crucially — it *closes* exhaustively (≈5.66M states) rather than truncating: it
    /// proves the mint gate and teardown sweep leave *no* reachable state within 7 hypercalls in
    /// which a grant or a half-open port names a Dead slot, across every create/destroy
    /// interleaving. This supersedes the earlier depth-8 form, which only *truncated* at the 1.5M
    /// cap (a lower bound, not a proof); because BFS visits shallower depths first, the truncated
    /// run had not even finished the depth-≤7 states (≈5.66M > 1.5M), so this closure strictly
    /// subsumes it *and* adds completeness. The raised cap is what lets it close; a
    /// memory-starved box falls back to a still-clean truncated lower bound (`expect_no_violation`
    /// tolerates that and reports it).
    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn domain_id_reuse_deep() {
        let mut cfg = reuse_cfg(7);
        cfg.max_states = 8_000_000;
        expect_no_violation(&cfg);
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

    /// The domain lifecycle, **saturated to an all-depths theorem**. With p2m but no grant,
    /// no map can back onto an owned frame, so no refcount ever grows without bound (pins are
    /// idempotent, links are capped at one per `(parent,slot)`) — the reachable set is finite.
    /// At depth 16 the frontier empties: 47,496 states, every reachable interleaving of birth,
    /// resource acquisition, delegation, and death proven to leave every `Dead` slot a clean,
    /// unprivileged shell — at all depths, not merely up to a bound. See `docs/TIER-B-CUTOFF.md`.
    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn domain_lifecycle_deep() {
        let states = expect_saturated(&lifecycle_cfg(16));
        assert!(
            states > 40_000,
            "lifecycle reachable set unexpectedly small: {states}"
        );
    }

    /// The deep delegation-forest sweep, **saturated to an all-depths theorem**. The control
    /// matrix over four domains is a bounded structure (each cell is `Absent`/`Root`/`Via(d)`,
    /// D+2 values, D² cells) with no refcount, so its reachable set is finite: at depth 12 the
    /// frontier empties (58,280 states). This is enough to build a depth-2 delegation chain
    /// (create the target, two intermediaries, delegate creator → A → B) and exercise every
    /// revoke and destroy against it — proving chain-restricted revocation, subtree cascades,
    /// and delegator-death cascades never leave an orphaned or cyclic edge, at **all** depths.
    /// The cycle-freedom itself is not a size-cutoff result — see `docs/TIER-B-CUTOFF.md` §2.4.
    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn delegation_forest_deep() {
        let states = expect_saturated(&delegation_cfg(12));
        assert!(
            states > 50_000,
            "delegation reachable set unexpectedly small: {states}"
        );
    }

    /// The deep event↔scheduler (lost-wakeup) sweep, **closed to a theorem**. Depth 7 *closes*
    /// exhaustively (≈2.12M states): every reachable state within 7 hypercalls under all
    /// event-channel and scheduler ops keeps no deliverable event resting on a blocked vCPU. Like
    /// the reuse sweep, this supersedes the earlier depth-8 form that only truncated at the 1.5M
    /// cap — a complete depth-7 proof rather than a partial depth-8 probe (BFS had not finished
    /// the depth-≤7 states at 1.5M, so this strictly subsumes it). The raised cap lets it close;
    /// a memory-starved box degrades to a still-clean truncated lower bound.
    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn evtchn_and_sched_seam_deep() {
        let mut cfg = evtchn_sched_cfg(7);
        cfg.max_states = 4_000_000;
        expect_no_violation(&cfg);
    }

    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn integrated_core_deep() {
        expect_no_violation(&all_cfg(5));
    }

    /// The deep affinity × full-core sweep, **closed to a theorem**. Depth 5 closes exhaustively
    /// (≈1.9M states — raised cap so it does not truncate): every reachable state within 5
    /// hypercalls of the two-pCPU, two-vCPU, all-subsystem world keeps every invariant, so a
    /// `Running` vCPU on an affinity-restricted pCPU coexisting with live grants, page tables,
    /// events, and delegation never breaks anything. The exhaustive proof that vCPU affinity is
    /// orthogonal to the other seams (Tier A).
    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn all_affinity_deep() {
        let mut cfg = all_affinity_cfg(5);
        cfg.max_states = 4_000_000;
        expect_no_violation(&cfg);
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

    /// The `saturated` flag is *sound* — the property the Tier-B all-depths theorems rest on.
    /// A saturated run is only meaningful if the flag means what it claims: the frontier truly
    /// emptied, so no state exists at any greater depth. This pins the mechanism itself (cheap
    /// enough for CI) so the deep `expect_saturated` sweeps stand on a checked instrument, not a
    /// trusted one.
    #[test]
    fn saturation_flag_is_sound() {
        // A tiny bounded world: create/destroy over two domains, nothing else. Its reachable
        // set is a handful of states, so it saturates almost immediately.
        let sat = |depth| {
            enumerate(&Config {
                create: true,
                destroy: true,
                depth,
                ..Config::tiny()
            })
        };

        // (a) It reports saturation, and the flag's meaning is real: once saturated at depth d,
        //     going deeper finds ZERO new states (an empty frontier has no successors to add).
        //     If `saturated` were set spuriously, a deeper run would grow the count.
        let shallow = sat(6);
        assert!(
            shallow.saturated,
            "tiny create/destroy world should saturate by depth 6"
        );
        assert!(!shallow.truncated);
        let deeper = sat(20);
        assert_eq!(
            shallow.states, deeper.states,
            "saturation claims completeness at all depths, yet a deeper run found more states — \
             the flag is unsound"
        );
        assert!(deeper.saturated);

        // (b) It is not set gratuitously: a genuinely UNBOUNDED config (grant+p2m, whose
        //     refcounts climb without bound) must NEVER report saturation — its frontier is
        //     non-empty at every depth, and a deeper run strictly grows. This is the negative
        //     half: the flag distinguishes finite from infinite, not just "did the loop end".
        let unbounded = |depth| {
            enumerate(&Config {
                grant: true,
                p2m: true,
                create: true,
                destroy: true,
                depth,
                ..Config::tiny()
            })
        };
        let g3 = unbounded(3);
        let g4 = unbounded(4);
        assert!(
            !g3.saturated,
            "grant+p2m is unbounded and must not report saturation"
        );
        assert!(!g4.saturated);
        assert!(
            g4.states > g3.states,
            "grant+p2m must keep growing depth over depth (unbounded reachable set): \
             {} at d3 vs {} at d4",
            g3.states,
            g4.states
        );
    }

    // ─── symmetry-reduction soundness validation ─────────────────────────────────────
    //
    // Symmetry reduction touches the dedup core, and a wrong canonicalization silently
    // merges two DIFFERENT orbits — hiding states, and any violation reachable only through
    // them. That is the worst possible outcome for a verification tool, so the reduction is
    // validated ruthlessly before a single theorem is leaned on it. These tests are CI-fast
    // (small configs, full enumeration both ways).

    /// A tiny p2m config exercising **frame** symmetry (3 frames ⇒ |G| = 3! = 6).
    fn sym_frame_cfg() -> Config {
        Config {
            p2m: true,
            create: true,
            destroy: true,
            frames: 3,
            levels: vec![PtLevel::L1, PtLevel::L2, PtLevel::L3],
            depth: 3,
            ..Config::tiny()
        }
    }

    /// A tiny evtchn+grant config exercising **frame × port × grant** symmetry
    /// (2 frames, 2 ports/dom, 2 grants/dom over 2 domains ⇒ |G| = 2 · 2!² · 2!² = 32) —
    /// the same shape as `reuse_cfg`, the flagship reduction target.
    fn sym_reuse_cfg() -> Config {
        reuse_cfg(3)
    }

    /// A tiny evtchn+sched config exercising **port** symmetry (2 ports/dom over 2 domains
    /// ⇒ |G| = 2!² = 4), with vCPU 0 correctly left fixed (its `notify_target` asymmetry).
    fn sym_evtchn_sched_cfg() -> Config {
        evtchn_sched_cfg(3)
    }

    /// Full BFS collecting one concrete `Hypervisor` per distinct (raw-keyed) reachable
    /// state — the ground-truth reachable set the reduction is validated against.
    fn reachable_states(cfg: &Config) -> Vec<Hypervisor> {
        let universe = ops(cfg);
        let init = Hypervisor::new(
            cfg.domains,
            cfg.ports,
            cfg.grants,
            cfg.vcpus,
            cfg.pcpus,
            cfg.frames,
        );
        let mut seen: std::collections::HashSet<StateKey> = std::collections::HashSet::new();
        let mut all = Vec::new();
        seen.insert(state_key(&init));
        let mut frontier = vec![init.clone()];
        all.push(init);
        for _ in 0..cfg.depth {
            let mut next = Vec::new();
            for hv in &frontier {
                for &(caller, call) in &universe {
                    let mut h = hv.clone();
                    let _: Result<HvOutcome, _> = h.dispatch(caller, call);
                    // Only invariant-holding states are enqueued; a clean config (asserted by
                    // the caller) has no others, so this matches `enumerate`'s reachable set.
                    if !h.invariants_hold() {
                        continue;
                    }
                    if seen.insert(state_key(&h)) {
                        next.push(h.clone());
                        all.push(h);
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }
        all
    }

    // Small configs that *saturate* (their BFS frontier goes empty), so `reachable_states`
    // returns the COMPLETE reachable set — which is genuinely *closed* under any automorphism
    // of the transition system, at all depths. (A merely depth-bounded reachable set is not
    // closed: a permutation need not preserve hypercall distance from `new()` — the allocator
    // makes low indices cheaper to reach — so `alloc unbound` at 2 hypercalls has a symmetric
    // image at 4, present in the full set but absent from a depth-3 slice. That is why closure
    // must be checked on a saturated set, not a truncated one.)
    fn sat_frame_cfg() -> Config {
        // Real p2m over 2 frames, one domain (frames owned, typed, pinned, linked). |G| = 2.
        Config {
            p2m: true,
            domains: 1,
            frames: 2,
            levels: vec![PtLevel::L1, PtLevel::L2],
            depth: 16,
            ..Config::tiny()
        }
    }
    fn sat_port_cfg() -> Config {
        // Event channels over dom0 alone (self-unbound + self-interdomain, so `remote_port`
        // is exercised), no create/destroy. Saturates at 129 states. |G| = 4.
        Config {
            evtchn: true,
            domains: 2,
            ports: 2,
            depth: 14,
            ..Config::tiny()
        }
    }
    fn sat_grant_cfg() -> Config {
        // Grants + create/destroy over one frame (no p2m ⇒ no unbounded refcount ⇒ saturates
        // at 2537). Exercises grant-entry perms and the mapping `gref` remap. |G| = 4.
        Config {
            grant: true,
            create: true,
            destroy: true,
            frames: 1,
            depth: 12,
            ..Config::tiny()
        }
    }
    fn sat_frame_grant_cfg() -> Config {
        // Grants over two frames: frame AND grant symmetry on a saturated set (26,345). |G| = 8.
        Config {
            frames: 2,
            depth: 10,
            ..sat_grant_cfg()
        }
    }

    /// **The soundness crux — the group is an automorphism of the transition system.** A
    /// *saturated* config's reachable set is complete, hence closed under any automorphism: for
    /// every reachable state and every group element, the permuted state is itself reachable. A
    /// group element that carries a reachable state OFF the reachable set is *not* a symmetry —
    /// its cross-reference remap is wrong, or the group wrongly includes it — and canonicalizing
    /// on it could merge distinct orbits. Checked directly over the whole group and every
    /// reachable state. Closure failing *is* the over-merge bug, surfaced at its source.
    fn assert_group_closes_saturated_set(cfg: &Config) {
        let out = enumerate(cfg);
        assert!(out.violation.is_none(), "config must be clean");
        assert!(
            out.saturated,
            "closure must be checked on a SATURATED (complete, closed) reachable set, not a \
             depth-bounded slice — this config did not saturate"
        );
        let grp = group(cfg);
        assert!(
            grp.len() > 1,
            "group must be non-trivial or the test proves nothing"
        );

        let states = reachable_states(cfg);
        let keyset: std::collections::HashSet<StateKey> = states.iter().map(state_key).collect();

        for hv in &states {
            let sn = Snapshot::from_hv(hv);
            for g in &grp {
                assert!(
                    keyset.contains(&snapshot_key(&permute(&sn, g))),
                    "a group element mapped a reachable state OFF the (complete) reachable set — \
                     not a symmetry (unsound). |G|={}, |R|={}",
                    grp.len(),
                    states.len()
                );
            }
        }
    }

    #[test]
    fn symmetry_group_closes_saturated_set_frames() {
        assert_group_closes_saturated_set(&sat_frame_cfg());
    }

    #[test]
    fn symmetry_group_closes_saturated_set_ports() {
        assert_group_closes_saturated_set(&sat_port_cfg());
    }

    #[test]
    fn symmetry_group_closes_saturated_set_grants() {
        assert_group_closes_saturated_set(&sat_grant_cfg());
    }

    /// Frame × grant symmetry together on a saturated set (|G| = 8 over 26,345 states) — the
    /// same combined group `reuse` and the deep sweeps use, checked all-depths. `#[ignore]`d
    /// only because 26k × 8 permutations is a second or two, more than the CI closure budget.
    #[test]
    #[ignore = "deeper saturated-closure validation — run with --release --ignored"]
    fn symmetry_group_closes_saturated_set_frame_grant() {
        assert_group_closes_saturated_set(&sat_frame_grant_cfg());
    }

    /// `canonical_key` is a genuine orbit function: constant on each orbit (invariant under
    /// the group action — which also checks `permute` composes as a group action) and
    /// distinguishing on a hand-built non-symmetric pair. The orbit-invariance direction is
    /// what licenses deduping on it; the separation direction is what stops it from merging
    /// everything.
    #[test]
    fn canonical_key_is_orbit_invariant_and_separating() {
        let cfg = sym_reuse_cfg();
        let grp = group(&cfg);
        for hv in reachable_states(&cfg) {
            let sn = Snapshot::from_hv(&hv);
            let canon = canonical_key(&sn, &grp);
            for g in &grp {
                // Permuting a state must not change its canonical key: min over the group of
                // the orbit of g·s is the same orbit, hence the same min.
                assert_eq!(
                    canon,
                    canonical_key(&permute(&sn, g), &grp),
                    "canonical key is not orbit-invariant"
                );
            }
        }
        // Separation: two states that are NOT related by any id-permutation must keep
        // distinct canonical keys. dom0 owning frame 0 typed as a page table is not symmetric
        // to dom0 owning it as a writable page (page type is not an id we permute).
        let mut a = Hypervisor::new(2, 2, 2, 1, 1, 2);
        a.dispatch(0, HvCall::P2mAllocate { mfn: 0 }).unwrap();
        a.dispatch(
            0,
            HvCall::P2mPin {
                mfn: 0,
                level: PtLevel::L1,
            },
        )
        .unwrap();
        let mut b = Hypervisor::new(2, 2, 2, 1, 1, 2);
        b.dispatch(0, HvCall::P2mAllocate { mfn: 0 }).unwrap();
        let gp = group(&Config {
            p2m: true,
            grant: true,
            ..Config::tiny()
        });
        assert_ne!(
            canonical_key(&Snapshot::from_hv(&a), &gp),
            canonical_key(&Snapshot::from_hv(&b), &gp),
            "canonical key wrongly merged two non-symmetric states"
        );
    }

    /// The reduced enumeration visits **exactly** the orbits the full one does — no orbit
    /// dropped (which would be unsound), none invented. The orbit count is computed
    /// independently of `canonical_key`'s min, by the *set* of keys in each state's orbit
    /// (two states share an orbit iff their orbit-key-sets are equal), so this is not
    /// circular with the reduced run. Also pins the count-sanity floor `|R| / |G| ≤ reduced ≤
    /// |R|`: a reduction cannot merge below the orbit-count floor.
    fn assert_reduction_faithful(cfg: &Config) {
        let mut full_cfg = cfg.clone();
        full_cfg.symmetry = false;
        let mut red_cfg = cfg.clone();
        red_cfg.symmetry = true;

        let full = enumerate(&full_cfg);
        let red = enumerate(&red_cfg);
        assert!(full.violation.is_none() && !full.truncated);
        assert!(red.violation.is_none() && !red.truncated);
        assert_eq!(
            red.saturated, full.saturated,
            "reduction must not change saturation"
        );

        let grp = group(cfg);
        let states = reachable_states(&full_cfg);
        // Each state's orbit, identified by the *set* of keys it reaches under the group
        // (independent of which representative `canonical_key` would pick).
        let orbits: std::collections::HashSet<std::collections::BTreeSet<StateKey>> = states
            .iter()
            .map(|hv| {
                let sn = Snapshot::from_hv(hv);
                grp.iter().map(|g| snapshot_key(&permute(&sn, g))).collect()
            })
            .collect();

        assert_eq!(
            red.states,
            orbits.len(),
            "reduced run must visit exactly one state per orbit ({} orbits in {} full states)",
            orbits.len(),
            full.states
        );
        assert!(
            red.states <= full.states,
            "reduction cannot grow the state count"
        );
        assert!(
            red.states.saturating_mul(grp.len()) >= full.states,
            "over-merged below the orbit-count floor |R|/|G|: reduced={} |G|={} full={}",
            red.states,
            grp.len(),
            full.states
        );
    }

    #[test]
    fn reduced_visits_exactly_the_full_orbits_frames() {
        assert_reduction_faithful(&sym_frame_cfg());
    }

    #[test]
    fn reduced_visits_exactly_the_full_orbits_reuse() {
        assert_reduction_faithful(&sym_reuse_cfg());
    }

    #[test]
    fn reduced_visits_exactly_the_full_orbits_evtchn_sched() {
        assert_reduction_faithful(&sym_evtchn_sched_cfg());
    }

    /// The reduced run **hides no reachable orbit** — the coverage-completeness soundness test,
    /// and the depth-robust one (it needs no saturation). This is the operational form of the
    /// brief's inject-a-bug check: a violation lives in some reachable state, whose orbit the
    /// reduced BFS must visit or the violation is hidden. It catches a *harmful over-merge*
    /// directly: if `canonical_key` wrongly merged two non-symmetric states s1, s2 with
    /// different successors, the reduced BFS expands only one representative and never generates
    /// s2's unique successor orbits — so `visited` would be strictly missing canonical keys that
    /// the full reachable set contains, and this `assert_eq` fires. (It cannot false-pass on
    /// such a merge, precisely because it expands only one representative per canonical key
    /// while `full_orbit_reps` is taken over *every* full-reachable state.) Run across all three
    /// permuted id kinds.
    fn assert_reduction_hides_no_orbit(cfg: &Config) {
        let mut red_cfg = cfg.clone();
        red_cfg.symmetry = true;

        let grp = group(cfg);
        // Every orbit the full (unreduced) reachable set touches, by its canonical rep.
        let full_orbit_reps: std::collections::HashSet<StateKey> = reachable_states(cfg)
            .iter()
            .map(|hv| canonical_key(&Snapshot::from_hv(hv), &grp))
            .collect();

        // The canonical keys the reduced BFS actually visits (expanding one rep per orbit).
        let visited = reduced_visited_keys(&red_cfg);

        assert_eq!(
            visited, full_orbit_reps,
            "reduced run's visited orbits differ from the full run's — a reachable orbit was \
             dropped (a harmful over-merge) or invented"
        );
    }

    /// The full four-level page-table hierarchy over **three frames**, driven to an all-depths
    /// theorem **that only symmetry reduction can reach**. Unreduced, this config's reachable
    /// set exceeds the state cap and never empties its frontier — it stays "argued-finite"
    /// (§1.2: pins idempotent, links capped ⇒ refcounts bounded) but *unmeasured*. With
    /// frame-symmetry reduction (the three frames are fully interchangeable, |G| = 3! = 6) the
    /// reachable set collapses to 1,030,856 orbit representatives and the frontier **does** go
    /// empty at depth 16 — proving the L1–L4 hierarchy invariants (`MislevelledLink`,
    /// write-xor-pagetable, exclusivity) hold in every reachable state at **every** depth, over
    /// a full four-level tree. This is symmetry reduction's headline payoff: converting a
    /// depth-axis *argument* into a *measured* all-depths theorem (`docs/TIER-B-CUTOFF.md`
    /// §2.5). Takes ~5 min in release — `#[ignore]`d like the other deep sweeps.
    fn sym_hierarchy_cfg(depth: u32) -> Config {
        Config {
            p2m: true,
            domains: 1,
            frames: 3,
            levels: vec![PtLevel::L1, PtLevel::L2, PtLevel::L3, PtLevel::L4],
            symmetry: true,
            depth,
            max_states: 3_000_000,
            ..Config::tiny()
        }
    }

    #[test]
    #[ignore = "deep exhaustive sweep — run on demand with --release --ignored"]
    fn hierarchy_saturates_only_under_symmetry_reduction() {
        // Reduced: the frontier empties — a measured all-depths theorem (≈1.03M reps).
        let states = expect_saturated(&sym_hierarchy_cfg(16));
        assert!(
            (900_000..1_200_000).contains(&states),
            "reduced saturated size out of expected band: {states}"
        );

        // Non-vacuity: the SAME config *unreduced* does NOT saturate within a cap that the
        // reduced run clears with room to spare — it truncates. So the reduction is precisely
        // what turns §1.2's finiteness argument into a measured empty frontier here.
        let mut full = sym_hierarchy_cfg(16);
        full.symmetry = false;
        full.max_states = 1_500_000;
        let out = enumerate(&full);
        assert!(
            out.truncated && !out.saturated,
            "expected the unreduced run to truncate at the cap, not saturate — reduction would \
             then be adding nothing"
        );
    }

    #[test]
    fn reduction_hides_no_reachable_orbit_frames() {
        assert_reduction_hides_no_orbit(&sym_frame_cfg());
    }

    #[test]
    fn reduction_hides_no_reachable_orbit_ports() {
        assert_reduction_hides_no_orbit(&sym_evtchn_sched_cfg());
    }

    #[test]
    fn reduction_hides_no_reachable_orbit_grants_and_ports() {
        assert_reduction_hides_no_orbit(&sym_reuse_cfg());
    }

    /// The set of canonical keys a reduced BFS visits (mirrors `enumerate`'s dedup exactly).
    fn reduced_visited_keys(cfg: &Config) -> std::collections::HashSet<StateKey> {
        let universe = ops(cfg);
        let init = Hypervisor::new(
            cfg.domains,
            cfg.ports,
            cfg.grants,
            cfg.vcpus,
            cfg.pcpus,
            cfg.frames,
        );
        let grp = group(cfg);
        let key = |hv: &Hypervisor| canonical_key(&Snapshot::from_hv(hv), &grp);
        let mut seen: std::collections::HashSet<StateKey> = std::collections::HashSet::new();
        seen.insert(key(&init));
        let mut frontier = vec![init];
        for _ in 0..cfg.depth {
            let mut next = Vec::new();
            for hv in &frontier {
                for &(caller, call) in &universe {
                    let mut h = hv.clone();
                    let _: Result<HvOutcome, _> = h.dispatch(caller, call);
                    if !h.invariants_hold() {
                        continue;
                    }
                    if seen.insert(key(&h)) {
                        next.push(h);
                    }
                }
            }
            frontier = next;
            if frontier.is_empty() {
                break;
            }
        }
        seen
    }
}
