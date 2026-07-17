// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Deterministic simulation.
//!
//! A `u64` seed drives a reproducible sequence of hypercalls and clock advances
//! through [`hv_core::HvCore`]. The core's `debug_assert!` invariants fire on every
//! transition, so a violation surfaces here — and the seed that produced it is the
//! whole reproducer. This is the FoundationDB discipline shrunk to a laptop.

use hv_core::evtchn::{PortState, System};
use hv_core::p2m::{PageType, PtLevel};
use hv_core::{
    grant, p2m, policy, prng::Prng, sched, HvCall, HvCore, HvOutcome, Hypercall, Hypervisor,
};
use hv_hal::TimeSource;

use crate::{FakeMemory, ManualClock};

/// The outcome of one simulated run — enough to assert determinism against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    /// Final credit balance.
    pub balance: u64,
    /// Final total granted.
    pub granted: u64,
    /// Final total spent.
    pub spent: u64,
    /// Final clock reading.
    pub ticks: u64,
}

/// Run one scenario derived from `seed` for `steps` hypercalls.
///
/// Deterministic by construction: identical `(seed, steps)` produce an identical
/// [`Outcome`], because the PRNG, the clock, and the dispatch are all pure given
/// the seed. Invariants are enforced inside `dispatch`; this function's job is
/// simply to generate a varied, replayable event stream.
pub fn run(seed: u64, steps: u32) -> Outcome {
    let mut core = HvCore::new();
    let mut mem = FakeMemory::new(4096);
    let clock = ManualClock::new();
    let mut rng = Prng::new(seed);

    for _ in 0..steps {
        // Advance time by a seed-derived amount so ordering is part of the replay.
        clock.advance(1 + u64::from(rng.below(16)));

        let call = match rng.below(2) {
            0 => Hypercall::Grant {
                amount: rng.below(1000),
            },
            _ => Hypercall::Spend {
                amount: rng.below(1000),
            },
        };

        // A `Spend` that exceeds the balance returns `Err` by design; the scenario
        // deliberately generates those to exercise the rejection path. The
        // conservation invariant is checked inside `dispatch` regardless.
        let _ = core.dispatch(&mut mem, &clock, call);
    }

    Outcome {
        balance: core.balance(),
        granted: core.granted(),
        spent: core.spent(),
        ticks: clock.now(),
    }
}

/// A comparable summary of a finished event-channel run — a census of port states
/// plus signal counts. Two runs from the same seed produce an identical summary.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EvtchnOutcome {
    pub free: u32,
    pub unbound: u32,
    pub interdomain: u32,
    pub virq: u32,
    pub ipi: u32,
    pub pending: u32,
    pub masked: u32,
    /// Whether the system's invariants hold at the end — asserted in release too.
    pub invariants_hold: bool,
}

impl EvtchnOutcome {
    fn of(sys: &System) -> Self {
        let mut o = EvtchnOutcome::default();
        for dom in 0..sys.domain_count() as u16 {
            for port in 0..sys.port_count(dom) as u32 {
                match sys.state_of(dom, port) {
                    Some(PortState::Free) => o.free += 1,
                    Some(PortState::Unbound { .. }) => o.unbound += 1,
                    Some(PortState::Interdomain { .. }) => o.interdomain += 1,
                    Some(PortState::Virq { .. }) => o.virq += 1,
                    Some(PortState::Ipi { .. }) => o.ipi += 1,
                    None => {}
                }
                if sys.is_pending(dom, port) {
                    o.pending += 1;
                }
                if sys.is_masked(dom, port) {
                    o.masked += 1;
                }
            }
        }
        o.invariants_hold = sys.invariants_hold();
        o
    }
}

/// Drive the event-channel [`System`] through a seed-derived sequence of operations
/// across a few domains. Same discipline as [`run`]: the core's `debug_assert!`
/// invariants fire on every transition, and the seed is the whole reproducer. This
/// is where interdomain reciprocity is stress-tested under interleaved close/bind
/// races — the exact shape of Xen's historical event-channel XSAs.
pub fn run_evtchn(seed: u64, steps: u32) -> EvtchnOutcome {
    const DOMAINS: u16 = 3;
    const PORTS: u32 = 8;

    let mut sys = System::new(DOMAINS as usize, PORTS as usize);
    let mut rng = Prng::new(seed);

    for _ in 0..steps {
        let dom = rng.below(u32::from(DOMAINS)) as u16;
        let port = rng.below(PORTS);
        match rng.below(8) {
            0 => {
                let remote = rng.below(u32::from(DOMAINS)) as u16;
                let _ = sys.alloc_unbound(dom, remote);
            }
            1 => {
                let remote = rng.below(u32::from(DOMAINS)) as u16;
                let remote_port = rng.below(PORTS);
                let _ = sys.bind_interdomain(dom, remote, remote_port);
            }
            2 => {
                let _ = sys.bind_virq(dom, rng.below(2), rng.below(4) as u8);
            }
            3 => {
                let _ = sys.bind_ipi(dom, rng.below(2));
            }
            4 => {
                let _ = sys.close(dom, port);
            }
            5 => {
                let _ = sys.send(dom, port);
            }
            6 => {
                let _ = if rng.below(2) == 0 {
                    sys.mask(dom, port)
                } else {
                    sys.unmask(dom, port)
                };
            }
            _ => {
                let _ = sys.consume(dom, port);
            }
        }
    }

    EvtchnOutcome::of(&sys)
}

/// A comparable summary of a finished grant-table run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct GrantOutcome {
    pub granted: u32,
    pub free: u32,
    pub active_maps: u32,
    /// Whether the system's invariants hold at the end — asserted in release too.
    pub invariants_hold: bool,
}

impl GrantOutcome {
    fn of(sys: &grant::System) -> Self {
        let mut o = GrantOutcome::default();
        for grantor in 0..sys.domain_count() as u16 {
            for gref in 0..sys.entry_count(grantor) as u32 {
                if sys.is_granted(grantor, gref) {
                    o.granted += 1;
                } else {
                    o.free += 1;
                }
            }
        }
        o.active_maps = sys.active_maps() as u32;
        o.invariants_hold = sys.invariants_hold();
        o
    }
}

/// Drive the grant-table [`grant::System`] through a seed-derived operation stream
/// across a few domains, tracking live handles so unmaps target real mappings. This
/// stresses the safety property under interleaving: an end_access racing live maps
/// must never succeed, and no mapping is ever left dangling.
pub fn run_grant(seed: u64, steps: u32) -> GrantOutcome {
    const DOMAINS: u16 = 3;
    const ENTRIES: u32 = 6;

    let mut sys = grant::System::new(DOMAINS as usize, ENTRIES as usize);
    let mut rng = Prng::new(seed);
    let mut handles: Vec<(u16, u32)> = Vec::new(); // (grantee, handle) of live maps

    for _ in 0..steps {
        let grantor = rng.below(u32::from(DOMAINS)) as u16;
        let gref = rng.below(ENTRIES);
        match rng.below(6) {
            0 => {
                let grantee = rng.below(u32::from(DOMAINS)) as u16;
                let readonly = rng.below(2) == 0;
                let frame = rng.below(64);
                let _ = sys.grant_access(grantor, gref, grantee, frame, readonly);
            }
            1 => {
                let _ = sys.end_access(grantor, gref);
            }
            2 | 5 => {
                let grantee = rng.below(u32::from(DOMAINS)) as u16;
                let writable = rng.below(2) == 0;
                if let Ok(h) = sys.map(grantee, grantor, gref, writable) {
                    handles.push((grantee, h));
                }
            }
            3 => {
                if !handles.is_empty() {
                    let idx = rng.below(handles.len() as u32) as usize;
                    let (grantee, handle) = handles.swap_remove(idx);
                    let _ = sys.unmap(grantee, handle);
                }
            }
            _ => {
                let grantee = rng.below(u32::from(DOMAINS)) as u16;
                let write = rng.below(2) == 0;
                let _ = sys.copy(grantee, grantor, gref, write);
            }
        }
    }

    GrantOutcome::of(&sys)
}

/// A comparable summary of a finished scheduler run — a census of vCPU run states,
/// physical-CPU occupancy, and total accrued runtime.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SchedOutcome {
    pub offline: u32,
    pub runnable: u32,
    pub running: u32,
    pub blocked: u32,
    pub busy_pcpus: u32,
    /// Total closed on-CPU time across all vCPUs. Monotonic in `steps` for a fixed
    /// seed, because per-vCPU runtime only ever grows.
    pub total_runtime: u64,
    /// Whether the system's invariants hold at the end — asserted in release too.
    pub invariants_hold: bool,
}

impl SchedOutcome {
    fn of(sys: &sched::System) -> Self {
        let mut o = SchedOutcome::default();
        for dom in 0..sys.domain_count() as u16 {
            for vcpu in 0..sys.vcpu_count(dom) as u32 {
                match sys.state_of(dom, vcpu) {
                    Some(sched::RunState::Offline) => o.offline += 1,
                    Some(sched::RunState::Runnable) => o.runnable += 1,
                    Some(sched::RunState::Running { .. }) => o.running += 1,
                    Some(sched::RunState::Blocked) => o.blocked += 1,
                    None => {}
                }
                o.total_runtime += sys.runtime(dom, vcpu).unwrap_or(0);
            }
        }
        o.busy_pcpus = sys.busy_pcpus() as u32;
        o.invariants_hold = sys.invariants_hold();
        o
    }
}

/// Drive the scheduler [`sched::System`] through a seed-derived stream of
/// admit/run/preempt/block/wake/offline operations across a few domains and physical
/// CPUs, cranking a [`ManualClock`] so time accounting is part of the replay. Same
/// discipline as the others: the core's `debug_assert!` fires on every transition, so
/// a broken pCPU-exclusivity reciprocity surfaces here with the seed as the whole
/// reproducer. This is where two vCPUs racing for one physical CPU is stress-tested.
pub fn run_sched(seed: u64, steps: u32) -> SchedOutcome {
    const DOMAINS: u16 = 3;
    const VCPUS: u32 = 2;
    const PCPUS: u32 = 2;

    let mut sys = sched::System::new(DOMAINS as usize, VCPUS as usize, PCPUS as usize);
    let mut rng = Prng::new(seed);
    let clock = ManualClock::new();

    for _ in 0..steps {
        // Advance time first so every run/preempt interval spans a seed-derived gap;
        // `now` is thus part of the replay exactly like the event ordering is.
        clock.advance(1 + u64::from(rng.below(16)));
        let now = clock.now();

        let dom = rng.below(u32::from(DOMAINS)) as u16;
        let vcpu = rng.below(VCPUS);
        let pcpu = rng.below(PCPUS);
        match rng.below(6) {
            0 => {
                let _ = sys.admit(dom, vcpu);
            }
            1 => {
                let _ = sys.run(dom, vcpu, pcpu, now);
            }
            2 => {
                let _ = sys.preempt(dom, vcpu, now);
            }
            3 => {
                let _ = sys.block(dom, vcpu, now);
            }
            4 => {
                let _ = sys.wake(dom, vcpu);
            }
            _ => {
                let _ = sys.offline(dom, vcpu, now);
            }
        }
    }

    SchedOutcome::of(&sys)
}

/// A comparable summary of a finished page-type run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct P2mOutcome {
    pub allocated: u32,
    /// Frames currently typed writable.
    pub writable_typed: u32,
    /// Frames currently typed as a page table.
    pub pagetable_typed: u32,
    /// Frames currently pinned as a page table.
    pub pinned: u32,
    /// Total existence references across all allocated frames.
    pub total_refs: u64,
    /// Whether the system's invariants hold at the end — asserted in release too.
    pub invariants_hold: bool,
}

impl P2mOutcome {
    fn of(sys: &p2m::System) -> Self {
        let mut o = P2mOutcome::default();
        for mfn in 0..sys.frame_count() as u32 {
            if sys.is_allocated(mfn) {
                o.allocated += 1;
                o.total_refs += u64::from(sys.refs(mfn).unwrap_or(0));
                match sys.current_type(mfn) {
                    Some(PageType::Writable) => o.writable_typed += 1,
                    Some(PageType::PageTable(_)) => o.pagetable_typed += 1,
                    None => {}
                }
                if sys.is_pinned(mfn) {
                    o.pinned += 1;
                }
            }
        }
        o.invariants_hold = sys.invariants_hold();
        o
    }
}

/// Drive the page-type [`p2m::System`] through a seed-derived stream of allocate / get
/// / put / get_type / put_type / pin / unpin / free operations across a few domains and
/// frames, tracking live typed references so put_type targets a type the frame actually
/// holds. Same discipline as the others: the core's `debug_assert!` fires on every
/// transition, so a broken writable-xor-pagetable exclusivity surfaces here with the
/// seed as the whole reproducer. This is where a page racing between writable and
/// page-table use — the shape of Xen's `PGT_*` typecount XSAs — is stress-tested.
pub fn run_p2m(seed: u64, steps: u32) -> P2mOutcome {
    const DOMAINS: u16 = 3;
    const FRAMES: u32 = 6;

    let mut sys = p2m::System::new(DOMAINS as usize, FRAMES as usize);
    let mut rng = Prng::new(seed);
    let mut typed: Vec<(u32, PageType)> = Vec::new(); // (mfn, type) of live typed refs

    for _ in 0..steps {
        let owner = rng.below(u32::from(DOMAINS)) as u16;
        let mfn = rng.below(FRAMES);
        match rng.below(9) {
            0 => {
                let _ = sys.allocate(owner, mfn);
            }
            1 => {
                let _ = sys.get(mfn);
            }
            2 => {
                let _ = sys.put(mfn);
            }
            3 | 4 => {
                let ty = if rng.below(2) == 0 {
                    PageType::Writable
                } else {
                    PageType::PageTable(pt_level(rng.below(4)))
                };
                if sys.get_type(mfn, ty).is_ok() {
                    typed.push((mfn, ty));
                }
            }
            5 => {
                if !typed.is_empty() {
                    let idx = rng.below(typed.len() as u32) as usize;
                    let (m, ty) = typed.swap_remove(idx);
                    let _ = sys.put_type(m, ty);
                }
            }
            6 => {
                let _ = sys.pin(owner, mfn, pt_level(rng.below(4)));
            }
            7 => {
                let _ = sys.unpin(owner, mfn);
            }
            _ => {
                let _ = sys.free(owner, mfn);
            }
        }
    }

    P2mOutcome::of(&sys)
}

/// A comparable summary of a finished scheduling-policy run.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PolicyOutcome {
    pub running: u32,
    pub total_runtime: u64,
    /// Smallest per-vCPU runtime among vCPUs that were ever admitted — a starvation
    /// witness.
    pub min_admitted_runtime: u64,
    /// Whether the mechanism invariant held after every `advance`.
    pub invariants_hold: bool,
    /// Whether the policy was work-conserving at every step: never an idle physical
    /// CPU while a vCPU sat runnable.
    pub work_conserving: bool,
}

/// Whether any physical CPU is idle while some vCPU is runnable — the negation of
/// work conservation, checked directly against the mechanism state.
fn has_idle_cpu_with_waiter(sys: &sched::System) -> bool {
    let idle = (0..sys.pcpu_count() as u32).any(|p| sys.occupant(p).is_none());
    if !idle {
        return false;
    }
    (0..sys.domain_count() as u16).any(|d| {
        (0..sys.vcpu_count(d) as u32).any(|v| sys.state_of(d, v) == Some(sched::RunState::Runnable))
    })
}

/// Drive the scheduling [`policy::Scheduler`] over the [`sched::System`] mechanism:
/// a seed churns vCPU availability (admit / block / wake / offline) while the policy
/// fills and preempts physical CPUs at each cranked tick. Asserts nothing itself —
/// it *reports* whether the mechanism stayed consistent and whether work conservation
/// held throughout, so the tests can turn those into properties over the seed space.
pub fn run_policy(seed: u64, steps: u32) -> PolicyOutcome {
    const DOMAINS: u16 = 2;
    const VCPUS: u32 = 3;
    const PCPUS: u32 = 2;

    let mut sys = sched::System::new(DOMAINS as usize, VCPUS as usize, PCPUS as usize);
    let mut pol = policy::Scheduler::new(DOMAINS as usize, VCPUS as usize, 4);
    // A spread of weights so the fair-share logic is exercised, not just the 1:1 case.
    for dom in 0..DOMAINS {
        for vcpu in 0..VCPUS {
            pol.set_weight(dom, vcpu, 1 + vcpu);
        }
    }
    let mut rng = Prng::new(seed);
    let clock = ManualClock::new();
    let mut admitted = [[false; VCPUS as usize]; DOMAINS as usize];

    let mut invariants_hold = true;
    let mut work_conserving = true;

    for _ in 0..steps {
        clock.advance(1 + u64::from(rng.below(8)));
        let now = clock.now();
        let dom = rng.below(u32::from(DOMAINS)) as u16;
        let vcpu = rng.below(VCPUS);

        // Churn availability. `run`/`preempt` are the policy's job, so this stream only
        // changes whether a vCPU *wants* a CPU, never places one directly.
        match rng.below(4) {
            0 => {
                if sys.admit(dom, vcpu).is_ok() {
                    admitted[dom as usize][vcpu as usize] = true;
                }
            }
            1 => {
                let _ = sys.block(dom, vcpu, now);
            }
            2 => {
                let _ = sys.wake(dom, vcpu);
            }
            _ => {
                let _ = sys.offline(dom, vcpu, now);
            }
        }

        // The policy fills/preempts to a fixpoint at this instant.
        pol.advance(&mut sys, now);

        invariants_hold &= sys.invariants_hold();
        work_conserving &= !has_idle_cpu_with_waiter(&sys);
    }

    let mut out = PolicyOutcome {
        invariants_hold,
        work_conserving,
        min_admitted_runtime: u64::MAX,
        ..PolicyOutcome::default()
    };
    let mut any_admitted = false;
    for dom in 0..DOMAINS {
        for vcpu in 0..VCPUS {
            if sys.is_running(dom, vcpu) {
                out.running += 1;
            }
            let rt = sys.runtime(dom, vcpu).unwrap_or(0);
            out.total_runtime += rt;
            if admitted[dom as usize][vcpu as usize] {
                any_admitted = true;
                out.min_admitted_runtime = out.min_admitted_runtime.min(rt);
            }
        }
    }
    if !any_admitted {
        out.min_admitted_runtime = 0;
    }
    out
}

/// Run `vcpus` vCPUs — all continuously runnable, never blocking — under the policy on
/// `pcpus` physical CPUs for `ticks` of time, with the given per-vCPU `weights`, and
/// return each vCPU's final accrued runtime. This is the controlled setting where
/// proportional fairness is meant to hold: with everyone always wanting the CPU, run
/// time should split in proportion to weight. Single domain, one vCPU per index.
#[cfg(test)]
fn run_policy_steady(
    weights: &[policy::Weight],
    pcpus: usize,
    quantum: u64,
    ticks: u64,
) -> Vec<u64> {
    let vcpus = weights.len();
    let mut sys = sched::System::new(1, vcpus, pcpus);
    let mut pol = policy::Scheduler::new(1, vcpus, quantum);
    for (v, &w) in weights.iter().enumerate() {
        sys.admit(0, v as u32).unwrap();
        pol.set_weight(0, v as u32, w);
    }
    // Step time in unit ticks so preemption points are resolved finely; the policy
    // re-fills and re-slices at each tick.
    for t in 1..=ticks {
        pol.advance(&mut sys, t);
    }
    // Close out every still-running interval so the final runtimes are comparable.
    for v in 0..vcpus {
        let _ = sys.preempt(0, v as u32, ticks);
    }
    (0..vcpus)
        .map(|v| sys.runtime(0, v as u32).unwrap_or(0))
        .collect()
}

/// A sleeper-fairness contrast: one CPU shared by two equal-weight vCPUs. `A` stays
/// runnable the whole time; `B` sleeps through a long warm-up (so `A` piles up
/// service) and then wakes to contend. Returns the number of contest-phase ticks each
/// vCPU held the CPU. With wake-boost on, `B` is placed at `A`'s level on waking and
/// the two share the contest evenly; with it off, `B` monopolises the CPU to catch up
/// on the service it missed while asleep, starving `A`.
#[cfg(test)]
fn run_sleeper(boost: bool) -> (u64, u64) {
    const WARMUP: u64 = 4000;
    const CONTEST: u64 = 2000;

    let mut sys = sched::System::new(1, 2, 1);
    let mut pol = policy::Scheduler::new(1, 2, 5);
    pol.set_wake_boost(boost);
    sys.admit(0, 0).unwrap();
    sys.admit(0, 1).unwrap();

    let mut t = 0u64;
    // B sleeps immediately; A runs the warm-up alone and accrues all the service.
    sys.block(0, 1, t).unwrap();
    for _ in 0..WARMUP {
        t += 1;
        pol.advance(&mut sys, t);
    }

    // B wakes; now both contend for the single CPU. Sample who holds it each tick.
    sys.wake(0, 1).unwrap();
    let (mut a_ticks, mut b_ticks) = (0u64, 0u64);
    for _ in 0..CONTEST {
        t += 1;
        pol.advance(&mut sys, t);
        match sys.occupant(0) {
            Some((0, 0)) => a_ticks += 1,
            Some((0, 1)) => b_ticks += 1,
            _ => {}
        }
    }
    (a_ticks, b_ticks)
}

/// A comparable census of a finished integrated-hypervisor run, spanning all three
/// subsystems plus the combined invariant verdict.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HvSummary {
    pub interdomain: u32,
    pub pending: u32,
    pub grants: u32,
    pub active_maps: u32,
    pub total_balance: u64,
    /// vCPUs currently on a physical CPU.
    pub running: u32,
    /// Total closed on-CPU time across all vCPUs.
    pub total_runtime: u64,
    /// Machine frames currently allocated.
    pub allocated_frames: u32,
    /// Machine frames currently carrying a type (writable or page table).
    pub typed_frames: u32,
    /// Machine frames currently pinned as a page table.
    pub pinned_frames: u32,
    /// Whether every subsystem's invariants hold at the end.
    pub invariants_hold: bool,
}

impl HvSummary {
    fn of(hv: &Hypervisor) -> Self {
        let mut s = HvSummary::default();
        let e = hv.evtchn();
        for dom in 0..e.domain_count() as u16 {
            for port in 0..e.port_count(dom) as u32 {
                if matches!(e.state_of(dom, port), Some(PortState::Interdomain { .. })) {
                    s.interdomain += 1;
                }
                if e.is_pending(dom, port) {
                    s.pending += 1;
                }
            }
        }
        let g = hv.grant();
        for grantor in 0..g.domain_count() as u16 {
            for gref in 0..g.entry_count(grantor) as u32 {
                if g.is_granted(grantor, gref) {
                    s.grants += 1;
                }
            }
        }
        s.active_maps = g.active_maps() as u32;
        for dom in 0..hv.domain_count() as u16 {
            s.total_balance += hv.balance(dom).unwrap_or(0);
        }
        let sc = hv.sched();
        for dom in 0..sc.domain_count() as u16 {
            for vcpu in 0..sc.vcpu_count(dom) as u32 {
                if sc.is_running(dom, vcpu) {
                    s.running += 1;
                }
                s.total_runtime += sc.runtime(dom, vcpu).unwrap_or(0);
            }
        }
        let p = hv.p2m();
        for mfn in 0..p.frame_count() as u32 {
            if p.is_allocated(mfn) {
                s.allocated_frames += 1;
                if p.current_type(mfn).is_some() {
                    s.typed_frames += 1;
                }
                if p.is_pinned(mfn) {
                    s.pinned_frames += 1;
                }
            }
        }
        s.invariants_hold = hv.invariants_hold();
        s
    }
}

/// Drive the whole integrated [`Hypervisor`] through a seed-derived stream of typed
/// hypercalls across all four subsystems, tracking live grants and handles so maps and
/// unmaps target real grants and their owners. One loop exercises credit, event
/// channels, grant tables, and page-type accounting through the single dispatch seam —
/// grants target real machine frames, so grant maps take page references and the
/// grant↔page-type cross-invariant is exercised too; one check covers the lot.
pub fn run_hypervisor(seed: u64, steps: u32) -> HvSummary {
    const DOMAINS: u16 = 3;
    const PORTS: u32 = 8;
    const GRANTS: u32 = 6;
    const VCPUS: u32 = 2;
    const PCPUS: u32 = 2;
    const FRAMES: u32 = 6;

    let mut hv = Hypervisor::new(
        DOMAINS as usize,
        PORTS as usize,
        GRANTS as usize,
        VCPUS as usize,
        PCPUS as usize,
        FRAMES as usize,
    );
    let mut rng = Prng::new(seed);
    let clock = ManualClock::new();
    let mut handles: Vec<(u16, u32)> = Vec::new(); // (grantee/owner, handle) of live maps
    let mut grants: Vec<(u16, u32, u16, bool)> = Vec::new(); // (grantor, gref, grantee, readonly)

    for _ in 0..steps {
        // Crank the clock so scheduler run/preempt intervals span seed-derived gaps.
        clock.advance(1 + u64::from(rng.below(16)));
        let now = clock.now();

        let caller = rng.below(u32::from(DOMAINS)) as u16;
        let port = rng.below(PORTS);
        let gref = rng.below(GRANTS);
        let vcpu = rng.below(VCPUS);
        let pcpu = rng.below(PCPUS);
        let mfn = rng.below(FRAMES);

        match rng.below(25) {
            0 => drop_ok(hv.dispatch(
                caller,
                HvCall::CreditGrant {
                    amount: rng.below(1000),
                },
            )),
            1 => drop_ok(hv.dispatch(
                caller,
                HvCall::CreditSpend {
                    amount: rng.below(1000),
                },
            )),
            2 => {
                let remote = rng.below(u32::from(DOMAINS)) as u16;
                drop_ok(hv.dispatch(caller, HvCall::EvtchnAllocUnbound { remote }));
            }
            3 => {
                let remote = rng.below(u32::from(DOMAINS)) as u16;
                let remote_port = rng.below(PORTS);
                drop_ok(hv.dispatch(
                    caller,
                    HvCall::EvtchnBindInterdomain {
                        remote,
                        remote_port,
                    },
                ));
            }
            4 => drop_ok(hv.dispatch(
                caller,
                HvCall::EvtchnBindVirq {
                    vcpu: rng.below(2),
                    virq: rng.below(4) as u8,
                },
            )),
            5 => drop_ok(hv.dispatch(caller, HvCall::EvtchnBindIpi { vcpu: rng.below(2) })),
            6 => drop_ok(hv.dispatch(caller, HvCall::EvtchnClose { port })),
            7 => drop_ok(hv.dispatch(caller, HvCall::EvtchnSend { port })),
            8 => {
                let call = if rng.below(2) == 0 {
                    HvCall::EvtchnMask { port }
                } else {
                    HvCall::EvtchnUnmask { port }
                };
                drop_ok(hv.dispatch(caller, call));
            }
            9 => drop_ok(hv.dispatch(caller, HvCall::EvtchnConsume { port })),
            10 => {
                // Build a *mappable* grant: the grantor owns the frame it grants
                // (allocate it first, best-effort), so a later map can take a real page
                // reference through the seam. Record it so the map arm can target it as
                // the right grantee — otherwise a random (grantor, gref) almost never
                // names a live grant and the coupled path is never exercised.
                let frame = mfn;
                let _ = hv.dispatch(caller, HvCall::P2mAllocate { mfn: frame });
                let grantee = rng.below(u32::from(DOMAINS)) as u16;
                let readonly = rng.below(2) == 0;
                if hv
                    .dispatch(
                        caller,
                        HvCall::GrantAccess {
                            gref,
                            grantee,
                            frame,
                            readonly,
                        },
                    )
                    .is_ok()
                {
                    grants.push((caller, gref, grantee, readonly));
                }
            }
            11 => drop_ok(hv.dispatch(caller, HvCall::GrantEndAccess { gref })),
            12 => {
                // Map a grant we actually created, as its named grantee. A read-write
                // grant is mapped writably (pinning the frame's type through the seam);
                // a read-only grant is mapped read-only (existence reference only).
                if !grants.is_empty() {
                    let idx = rng.below(grants.len() as u32) as usize;
                    let (grantor, ggref, grantee, readonly) = grants[idx];
                    let writable = !readonly;
                    if let Ok(HvOutcome::Handle(h)) = hv.dispatch(
                        grantee,
                        HvCall::GrantMap {
                            grantor,
                            gref: ggref,
                            writable,
                        },
                    ) {
                        handles.push((grantee, h));
                    }
                }
            }
            13 => {
                if !handles.is_empty() {
                    let idx = rng.below(handles.len() as u32) as usize;
                    let (owner, handle) = handles.swap_remove(idx);
                    drop_ok(hv.dispatch(owner, HvCall::GrantUnmap { handle }));
                }
            }
            14 => {
                let grantor = rng.below(u32::from(DOMAINS)) as u16;
                drop_ok(hv.dispatch(
                    caller,
                    HvCall::GrantCopy {
                        grantor,
                        gref,
                        write: rng.below(2) == 0,
                    },
                ));
            }
            15 => drop_ok(hv.dispatch(caller, HvCall::SchedAdmit { vcpu })),
            16 => drop_ok(hv.dispatch(caller, HvCall::SchedRun { vcpu, pcpu, now })),
            17 => drop_ok(hv.dispatch(caller, HvCall::SchedPreempt { vcpu, now })),
            18 => drop_ok(hv.dispatch(caller, HvCall::SchedBlock { vcpu, now })),
            19 => drop_ok(hv.dispatch(caller, HvCall::SchedWake { vcpu })),
            20 => drop_ok(hv.dispatch(caller, HvCall::SchedOffline { vcpu, now })),
            21 => drop_ok(hv.dispatch(caller, HvCall::P2mAllocate { mfn })),
            22 => drop_ok(hv.dispatch(caller, HvCall::P2mFree { mfn })),
            23 => drop_ok(hv.dispatch(
                caller,
                HvCall::P2mPin {
                    mfn,
                    level: pt_level(mfn),
                },
            )),
            _ => drop_ok(hv.dispatch(caller, HvCall::P2mUnpin { mfn })),
        }
    }

    HvSummary::of(&hv)
}

/// Discard a dispatch result — many calls fail by design (spend beyond balance,
/// send on a free port), and that is part of what the sim exercises.
fn drop_ok(result: Result<HvOutcome, hv_core::HvError>) {
    let _ = result;
}

/// Map a seed-derived number to a paging level, so a run spreads pins and page-table
/// references across all four levels rather than collapsing to one.
fn pt_level(n: u32) -> PtLevel {
    match n % 4 {
        0 => PtLevel::L1,
        1 => PtLevel::L2,
        2 => PtLevel::L3,
        _ => PtLevel::L4,
    }
}

/// A comparable summary of a finished event↔scheduler seam run. The counts are
/// *observed transitions*, not a resting census: a fired wake looks identical at rest
/// to a manual one, so the only way to prove the seam path is reached is to watch it
/// happen.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SeamOutcome {
    /// Times a send or unmask actually woke a `Blocked` vCPU through the seam
    /// (`Blocked` → `Runnable` across the signalling dispatch).
    pub wakes: u32,
    /// Times a block was a no-op because the vCPU already held a deliverable event —
    /// the block-race half of the invariant (Xen's `SCHEDOP_block` re-check).
    pub block_noops: u32,
    /// vCPUs still `Blocked` at the end.
    pub blocked: u32,
    /// Whether the integrated invariant — including no-lost-wakeup — held after every
    /// step, not just at the end.
    pub invariants_hold: bool,
}

/// Drive the integrated [`Hypervisor`] through a seed-derived stream *biased to fire the
/// event↔scheduler seam*: every vCPU gets an IPI port and one interdomain channel is
/// established, so a blocked vCPU can always be woken by signalling a port that
/// notify-targets it. The loop blocks, signals, masks/unmasks, and churns run state on
/// the *same* vCPUs, so blocks and sends actually align — where the generic
/// `run_hypervisor` only rarely does. It observes each send/unmask for a real
/// `Blocked` → `Runnable` wake and each block for a work-pending no-op, so a test can
/// assert the seam path is genuinely exercised, while the integrated invariant is
/// checked after every step.
pub fn run_seam(seed: u64, steps: u32) -> SeamOutcome {
    const DOMAINS: u16 = 2;
    const VCPUS: u32 = 2;
    const PCPUS: u32 = 2;
    const PORTS: u32 = 8;
    const GRANTS: u32 = 1;
    const FRAMES: u32 = 1;

    let mut hv = Hypervisor::new(
        DOMAINS as usize,
        PORTS as usize,
        GRANTS as usize,
        VCPUS as usize,
        PCPUS as usize,
        FRAMES as usize,
    );
    let clock = ManualClock::new();
    let mut rng = Prng::new(seed);

    // Admit every vCPU and give it an IPI port — so any vCPU the loop blocks can be
    // woken by signalling its own port, keeping the wake path reachable from every
    // state. `ipi[dom][vcpu]` is that port.
    let mut ipi = [[0u32; VCPUS as usize]; DOMAINS as usize];
    for dom in 0..DOMAINS {
        for vcpu in 0..VCPUS {
            hv.dispatch(dom, HvCall::SchedAdmit { vcpu }).unwrap();
            if let Ok(HvOutcome::Port(p)) = hv.dispatch(dom, HvCall::EvtchnBindIpi { vcpu }) {
                ipi[dom as usize][vcpu as usize] = p;
            }
        }
    }
    // One interdomain channel: domain 1 opens a port for domain 0, domain 0 binds it.
    // Signalling domain 0's end wakes domain 1's vCPU 0 (the interdomain notify
    // default) — the cross-domain wake, distinct from the same-domain IPI path.
    let inter = match hv.dispatch(1, HvCall::EvtchnAllocUnbound { remote: 0 }) {
        Ok(HvOutcome::Port(u)) => match hv.dispatch(
            0,
            HvCall::EvtchnBindInterdomain {
                remote: 1,
                remote_port: u,
            },
        ) {
            Ok(HvOutcome::Port(l)) => Some(l),
            _ => None,
        },
        _ => None,
    };

    let mut out = SeamOutcome {
        invariants_hold: true,
        ..SeamOutcome::default()
    };

    for _ in 0..steps {
        clock.advance(1 + u64::from(rng.below(8)));
        let now = clock.now();
        let dom = rng.below(u32::from(DOMAINS)) as u16;
        let vcpu = rng.below(VCPUS);
        let pcpu = rng.below(PCPUS);
        let p = ipi[dom as usize][vcpu as usize];

        match rng.below(8) {
            0 => {
                // Block this vCPU. If it was runnable/running yet stayed put, the seam
                // refused the block because a deliverable event already targets it.
                let before = hv.sched().state_of(dom, vcpu);
                drop_ok(hv.dispatch(dom, HvCall::SchedBlock { vcpu, now }));
                let after = hv.sched().state_of(dom, vcpu);
                let was_blockable = matches!(
                    before,
                    Some(sched::RunState::Runnable) | Some(sched::RunState::Running { .. })
                );
                if was_blockable && after == before {
                    out.block_noops += 1;
                }
            }
            1 => {
                // Signal this vCPU's own IPI — its notify target is exactly `vcpu`.
                let before = hv.sched().state_of(dom, vcpu);
                drop_ok(hv.dispatch(dom, HvCall::EvtchnSend { port: p }));
                if woke(before, hv.sched().state_of(dom, vcpu)) {
                    out.wakes += 1;
                }
            }
            2 => drop_ok(hv.dispatch(dom, HvCall::EvtchnMask { port: p })),
            3 => {
                // Unmask — the deferred deliverable edge; may wake a vCPU that blocked
                // while its port was pending-but-masked.
                let before = hv.sched().state_of(dom, vcpu);
                drop_ok(hv.dispatch(dom, HvCall::EvtchnUnmask { port: p }));
                if woke(before, hv.sched().state_of(dom, vcpu)) {
                    out.wakes += 1;
                }
            }
            4 => drop_ok(hv.dispatch(dom, HvCall::SchedWake { vcpu })),
            5 => drop_ok(hv.dispatch(dom, HvCall::SchedRun { vcpu, pcpu, now })),
            6 => drop_ok(hv.dispatch(dom, HvCall::SchedPreempt { vcpu, now })),
            _ => {
                // Signal the interdomain channel's sender end — wakes domain 1's vCPU 0
                // if it is blocked (the cross-domain path).
                if let Some(l) = inter {
                    let before = hv.sched().state_of(1, 0);
                    drop_ok(hv.dispatch(0, HvCall::EvtchnSend { port: l }));
                    if woke(before, hv.sched().state_of(1, 0)) {
                        out.wakes += 1;
                    }
                }
            }
        }

        out.invariants_hold &= hv.invariants_hold();
    }

    for dom in 0..DOMAINS {
        for vcpu in 0..VCPUS {
            if hv.sched().state_of(dom, vcpu) == Some(sched::RunState::Blocked) {
                out.blocked += 1;
            }
        }
    }
    out
}

/// Whether a run-state pair is a seam wake: `Blocked` before, `Runnable` after.
fn woke(before: Option<sched::RunState>, after: Option<sched::RunState>) -> bool {
    before == Some(sched::RunState::Blocked) && after == Some(sched::RunState::Runnable)
}

/// A comparable summary of a finished domain-teardown run. The counts are *observed
/// outcomes* of the destroy calls issued, so a test can prove both the refuse-if-busy
/// and the clean-teardown paths are genuinely reached — and that the postcondition
/// held every time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DestroyOutcome {
    /// Destroy calls that tore a domain down (`Ok`).
    pub teardowns: u32,
    /// Destroy calls refused because a foreign domain held a live map (`DomainBusy`).
    pub busy_refusals: u32,
    /// Whether every destroy matched its precondition and left a proper empty shell:
    /// refused exactly when a foreign map stood, and otherwise reduced the target to
    /// nothing-live. A single mismatch flips this false for the whole run.
    pub postcondition_held: bool,
    /// Whether the integrated invariant held after every step, not just at the end.
    pub invariants_hold: bool,
}

/// Whether `target` has been reduced to an empty but still-existent shell — the
/// teardown postcondition, checked from the sim through public queries: it holds no
/// port, no online vCPU, offers or holds no grant, and owns no frame.
fn is_empty_shell(hv: &Hypervisor, target: u16) -> bool {
    let e = hv.evtchn();
    let no_ports =
        (0..e.port_count(target) as u32).all(|p| e.state_of(target, p) == Some(PortState::Free));
    let sc = hv.sched();
    let no_vcpus = (0..sc.vcpu_count(target) as u32)
        .all(|v| sc.state_of(target, v) == Some(sched::RunState::Offline));
    let g = hv.grant();
    let no_grants = (0..g.entry_count(target) as u32).all(|gr| !g.is_granted(target, gr));
    let no_maps = !g.holds_any_map(target);
    let p = hv.p2m();
    let no_frames = (0..p.frame_count() as u32).all(|m| p.owner_of(m) != Some(target));
    no_ports && no_vcpus && no_grants && no_maps && no_frames
}

/// Drive the integrated [`Hypervisor`] through a seed-derived stream that *builds
/// domains up* across all four subsystems — ports, vCPUs on physical CPUs, grants,
/// live maps (foreign and self), pinned and plain frames — and periodically issues a
/// [`HvCall::DomainDestroy`] against a random target. Whole-domain teardown is the
/// operation that welds every subsystem and both seams at once, so this is where it is
/// stress-tested under interleaving.
///
/// Each destroy is checked against its own precondition: [`grant::System::has_foreign_map`]
/// predicts the outcome exactly — refuse (`DomainBusy`) iff a foreign domain holds a
/// live map of one of the target's frames, tear down cleanly otherwise — and every
/// clean teardown must leave an empty shell (`is_empty_shell`). The integrated
/// invariant is asserted after every step, so a mis-ordered teardown (a freed port with
/// a live peer, a freed on-CPU vCPU, a foreign-mapped freed frame, a deliverable event
/// on an offlined vCPU) surfaces here with the seed as the whole reproducer.
pub fn run_destroy(seed: u64, steps: u32) -> DestroyOutcome {
    const DOMAINS: u16 = 3;
    const PORTS: u32 = 6;
    const GRANTS: u32 = 4;
    const VCPUS: u32 = 2;
    const PCPUS: u32 = 2;
    const FRAMES: u32 = 6;

    let mut hv = Hypervisor::new(
        DOMAINS as usize,
        PORTS as usize,
        GRANTS as usize,
        VCPUS as usize,
        PCPUS as usize,
        FRAMES as usize,
    );
    let clock = ManualClock::new();
    let mut rng = Prng::new(seed);
    let mut handles: Vec<(u16, u32)> = Vec::new(); // (grantee, handle) of live maps
    let mut grants: Vec<(u16, u32, u16, bool)> = Vec::new(); // (grantor, gref, grantee, readonly)

    let mut out = DestroyOutcome {
        teardowns: 0,
        busy_refusals: 0,
        postcondition_held: true,
        invariants_hold: true,
    };

    for _ in 0..steps {
        clock.advance(1 + u64::from(rng.below(16)));
        let now = clock.now();
        let caller = rng.below(u32::from(DOMAINS)) as u16;
        let port = rng.below(PORTS);
        let gref = rng.below(GRANTS);
        let vcpu = rng.below(VCPUS);
        let pcpu = rng.below(PCPUS);
        let mfn = rng.below(FRAMES);

        match rng.below(16) {
            0 => {
                let remote = rng.below(u32::from(DOMAINS)) as u16;
                drop_ok(hv.dispatch(caller, HvCall::EvtchnAllocUnbound { remote }));
            }
            1 => {
                let remote = rng.below(u32::from(DOMAINS)) as u16;
                let remote_port = rng.below(PORTS);
                drop_ok(hv.dispatch(
                    caller,
                    HvCall::EvtchnBindInterdomain {
                        remote,
                        remote_port,
                    },
                ));
            }
            2 => drop_ok(hv.dispatch(caller, HvCall::EvtchnBindIpi { vcpu })),
            3 => drop_ok(hv.dispatch(caller, HvCall::EvtchnClose { port })),
            4 => drop_ok(hv.dispatch(caller, HvCall::EvtchnSend { port })),
            5 => {
                // A mappable grant: the grantor allocates the frame it grants (so a
                // later map takes a real page reference through the seam). Record it so
                // the map arm can target it as the right grantee — grantee may be the
                // grantor itself, so self-grants are exercised too.
                let frame = mfn;
                let _ = hv.dispatch(caller, HvCall::P2mAllocate { mfn: frame });
                let grantee = rng.below(u32::from(DOMAINS)) as u16;
                let readonly = rng.below(2) == 0;
                if hv
                    .dispatch(
                        caller,
                        HvCall::GrantAccess {
                            gref,
                            grantee,
                            frame,
                            readonly,
                        },
                    )
                    .is_ok()
                {
                    grants.push((caller, gref, grantee, readonly));
                }
            }
            6 => {
                if !grants.is_empty() {
                    let idx = rng.below(grants.len() as u32) as usize;
                    let (grantor, ggref, grantee, readonly) = grants[idx];
                    if let Ok(HvOutcome::Handle(h)) = hv.dispatch(
                        grantee,
                        HvCall::GrantMap {
                            grantor,
                            gref: ggref,
                            writable: !readonly,
                        },
                    ) {
                        handles.push((grantee, h));
                    }
                }
            }
            7 => {
                if !handles.is_empty() {
                    let idx = rng.below(handles.len() as u32) as usize;
                    let (owner, handle) = handles.swap_remove(idx);
                    drop_ok(hv.dispatch(owner, HvCall::GrantUnmap { handle }));
                }
            }
            8 => drop_ok(hv.dispatch(caller, HvCall::SchedAdmit { vcpu })),
            9 => drop_ok(hv.dispatch(caller, HvCall::SchedRun { vcpu, pcpu, now })),
            10 => drop_ok(hv.dispatch(caller, HvCall::SchedBlock { vcpu, now })),
            11 => drop_ok(hv.dispatch(caller, HvCall::P2mAllocate { mfn })),
            12 => drop_ok(hv.dispatch(
                caller,
                HvCall::P2mPin {
                    mfn,
                    level: pt_level(mfn),
                },
            )),
            13 => drop_ok(hv.dispatch(caller, HvCall::P2mFree { mfn })),
            _ => {
                // Tear a domain down. Its precondition predicts the outcome exactly, so
                // check the two against each other and verify the resulting shape.
                let target = rng.below(u32::from(DOMAINS)) as u16;
                let foreign = hv.grant().has_foreign_map(target);
                match hv.dispatch(caller, HvCall::DomainDestroy { target, now }) {
                    Ok(HvOutcome::Done) => {
                        out.teardowns += 1;
                        // A clean teardown must not have had a foreign map, and must
                        // leave nothing live pointing into the target.
                        if foreign || !is_empty_shell(&hv, target) {
                            out.postcondition_held = false;
                        }
                    }
                    Err(hv_core::HvError::DomainBusy) => {
                        out.busy_refusals += 1;
                        // A refusal must have had a foreign map (and, being a no-op,
                        // leaves the target as busy as it was — nothing to check here).
                        if !foreign {
                            out.postcondition_held = false;
                        }
                    }
                    other => panic!("unexpected destroy outcome {other:?}"),
                }
            }
        }

        out.invariants_hold &= hv.invariants_hold();
    }

    out
}

/// A census of a finished page-table run: how many frames ended up typed at each paging
/// level, how many ordinary leaves, the live edge count, and whether the hierarchical
/// invariant held after every step.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PtabOutcome {
    pub l4: u32,
    pub l3: u32,
    pub l2: u32,
    pub l1: u32,
    /// Frames typed writable — under this driver, the writable leaves an L1 table maps.
    pub leaves: u32,
    pub active_links: u32,
    /// Read-only leaves installed onto a frame that was *already a page table* — the
    /// linear-map case, where a guest maps one of its own tables read-only to read its
    /// PTEs while the CPU still walks it. A witness that the read-only-onto-page-table
    /// path (writable-xor-pagetable coexistence) is actually reached under interleaving.
    pub ro_onto_pagetable: u32,
    /// Whether the whole-system page invariant — including hierarchical
    /// level-correctness — held after every step.
    pub invariants_hold: bool,
}

impl PtabOutcome {
    fn of(sys: &p2m::System, invariants_hold: bool) -> Self {
        let mut o = PtabOutcome {
            invariants_hold,
            active_links: sys.active_links() as u32,
            ..PtabOutcome::default()
        };
        for mfn in 0..sys.frame_count() as u32 {
            match sys.current_type(mfn) {
                Some(PageType::PageTable(PtLevel::L4)) => o.l4 += 1,
                Some(PageType::PageTable(PtLevel::L3)) => o.l3 += 1,
                Some(PageType::PageTable(PtLevel::L2)) => o.l2 += 1,
                Some(PageType::PageTable(PtLevel::L1)) => o.l1 += 1,
                Some(PageType::Writable) => o.leaves += 1,
                None => {}
            }
        }
        o
    }
}

/// Try to install one valid page-table entry: pick a table `parent`, a free `slot`, a
/// `child` the same domain owns, and link them. Returns `true` iff it installed a
/// *read-only leaf onto a frame that was already a page table* — the linear-map case.
///
/// A seed bit chooses read-only or writable. A **writable** entry (or any interior one)
/// needs an *untyped* child, so the link establishes it one level down and the driver
/// grows L4→…→leaf trees rather than bouncing off type conflicts. A **read-only leaf**
/// (under an `L1`) imposes no type, so it may point at *any* frame the owner holds —
/// including one already typed as a page table, exercising the read-only-view-of-a-table
/// coexistence. On success the `(parent, slot)` edge is recorded for a later unlink.
fn try_link(sys: &mut p2m::System, rng: &mut Prng, links: &mut Vec<(u32, u32)>) -> bool {
    // Candidate parents: any frame currently typed as a page table.
    let parents: Vec<u32> = (0..sys.frame_count() as u32)
        .filter(|&m| matches!(sys.current_type(m), Some(PageType::PageTable(_))))
        .collect();
    if parents.is_empty() {
        return false;
    }
    let parent = parents[rng.below(parents.len() as u32) as usize];
    let slot = rng.below(p2m::TABLE_SLOTS);
    if sys.child_at(parent, slot).is_some() {
        return false; // slot occupied — leave it for another step
    }
    let owner = match sys.owner_of(parent) {
        Some(o) => o,
        None => return false,
    };
    // A read-only *leaf* (only meaningful under an L1 parent) may point at any allocated
    // frame; every other entry needs an untyped child to establish the level below.
    let ro_leaf =
        rng.below(2) == 0 && sys.current_type(parent) == Some(PageType::PageTable(PtLevel::L1));
    let children: Vec<u32> = (0..sys.frame_count() as u32)
        .filter(|&m| {
            m != parent
                && sys.owner_of(m) == Some(owner)
                && if ro_leaf {
                    sys.is_allocated(m)
                } else {
                    sys.current_type(m).is_none()
                }
        })
        .collect();
    if children.is_empty() {
        return false;
    }
    let child = children[rng.below(children.len() as u32) as usize];
    let onto_pagetable = ro_leaf && matches!(sys.current_type(child), Some(PageType::PageTable(_)));
    if sys.link(owner, parent, slot, child, !ro_leaf).is_ok() {
        links.push((parent, slot));
        onto_pagetable
    } else {
        false
    }
}

/// Drive the page-type [`p2m::System`] through a seed-derived stream that *builds
/// page-table trees*: allocate frames, pin some as roots at each of the four levels, and
/// link untyped children one level down to grow L4→L3→L2→L1→leaf chains, unlinking and
/// freeing as it goes. This is where the hierarchical type invariant — every entry points
/// exactly one level down — is stress-tested under interleaving: the core's `debug_assert!`
/// fires on every transition, so a mislevelled edge surfaces here with the seed as the
/// whole reproducer. This is the multi-level cousin of the write-xor stress in [`run_p2m`].
pub fn run_ptab(seed: u64, steps: u32) -> PtabOutcome {
    const DOMAINS: u16 = 2;
    const FRAMES: u32 = 8;

    let mut sys = p2m::System::new(DOMAINS as usize, FRAMES as usize);
    let mut rng = Prng::new(seed);
    let mut links: Vec<(u32, u32)> = Vec::new(); // (parent, slot) of live edges to unlink

    let mut invariants_hold = true;
    let mut ro_onto_pagetable = 0u32;
    for _ in 0..steps {
        let mfn = rng.below(FRAMES);
        match rng.below(8) {
            0 => {
                let owner = rng.below(u32::from(DOMAINS)) as u16;
                let _ = sys.allocate(owner, mfn);
            }
            1 => {
                // Pin an untyped frame as a fresh root at a seed-chosen level.
                if let Some(owner) = sys.owner_of(mfn) {
                    let _ = sys.pin(owner, mfn, pt_level(rng.below(4)));
                }
            }
            2..=4 => {
                ro_onto_pagetable += try_link(&mut sys, &mut rng, &mut links) as u32;
            }
            5 => {
                if !links.is_empty() {
                    let idx = rng.below(links.len() as u32) as usize;
                    let (parent, slot) = links.swap_remove(idx);
                    if let Some(owner) = sys.owner_of(parent) {
                        let _ = sys.unlink(owner, parent, slot);
                    }
                }
            }
            6 => {
                if let Some(owner) = sys.owner_of(mfn) {
                    let _ = sys.unpin(owner, mfn);
                }
            }
            _ => {
                if let Some(owner) = sys.owner_of(mfn) {
                    let _ = sys.free(owner, mfn);
                }
            }
        }
        invariants_hold &= sys.invariants_hold();
    }

    PtabOutcome {
        ro_onto_pagetable,
        ..PtabOutcome::of(&sys, invariants_hold)
    }
}

/// A census of a finished cross-domain page-table run. The counts are *observed
/// outcomes*, so a test can prove the authorized foreign-link path is reached, the
/// unauthorized one is refused, and a grant can't be revoked out from under a live entry.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ForeignOutcome {
    /// Cross-domain entries successfully installed (a domain mapped another's frame).
    pub links: u32,
    /// Of those, the *read-only* ones — a foreign leaf authorized by any grant (contrast
    /// a writable leaf, which needs a read-write grant). A witness that the read-only
    /// cross-domain path is reached, not just the writable one.
    pub ro_links: u32,
    /// Foreign links refused for want of a grant of matching permission
    /// (`HvError::Unauthorized`) — no grant at all, or a writable entry over a read-only
    /// grant.
    pub unauthorized: u32,
    /// Grant revocations refused because a live foreign entry still relied on the grant.
    pub revoke_blocks: u32,
    /// Whether the integrated invariant — including foreign-link authorization — held
    /// after every step.
    pub invariants_hold: bool,
}

/// Drive the integrated [`Hypervisor`] through a seed-derived stream *biased to exercise
/// cross-domain page-table sharing*. Two domains each own an `L1` table; the loop grants
/// data frames across the domain boundary — read-only or read-write by a seed bit — maps
/// granted foreign frames into the other domain's table at a seed-chosen access, unlinks
/// them, and revokes grants. It also attempts *unauthorized* foreign links (no grant, or a
/// writable entry over a read-only grant) to witness the isolation guard firing. The
/// authorization invariant — every cross-domain entry backed by a grant of matching
/// permission — is checked after every step, so a breach surfaces here with the seed as
/// the whole reproducer.
pub fn run_foreign(seed: u64, steps: u32) -> ForeignOutcome {
    const DOMAINS: u16 = 2;
    const GRANTS: u32 = 6;
    const FRAMES: u32 = 8;
    // Frame `d` is domain `d`'s L1 table; the rest are data frames to grant and map.
    const TABLE0: u32 = 0;
    const TABLE1: u32 = 1;
    const FIRST_DATA: u32 = 2;

    let mut hv = Hypervisor::new(DOMAINS as usize, 1, GRANTS as usize, 1, 1, FRAMES as usize);
    // Stand up one L1 table per domain, and hand each data frame to an owner.
    for (dom, table) in [(0u16, TABLE0), (1u16, TABLE1)] {
        hv.dispatch(dom, HvCall::P2mAllocate { mfn: table })
            .unwrap();
        hv.dispatch(
            dom,
            HvCall::P2mPin {
                mfn: table,
                level: PtLevel::L1,
            },
        )
        .unwrap();
    }
    for mfn in FIRST_DATA..FRAMES {
        let owner = (mfn % u32::from(DOMAINS)) as u16;
        hv.dispatch(owner, HvCall::P2mAllocate { mfn }).unwrap();
    }
    let table_of = |dom: u16| if dom == 0 { TABLE0 } else { TABLE1 };

    let mut rng = Prng::new(seed);
    let mut grants: Vec<(u16, u32, u16, u32)> = Vec::new(); // (grantor, gref, grantee, frame)
    let mut links: Vec<(u16, u32, u32)> = Vec::new(); // (linker, parent table, slot)
    let mut out = ForeignOutcome {
        invariants_hold: true,
        ..ForeignOutcome::default()
    };

    for _ in 0..steps {
        match rng.below(6) {
            0 => {
                // Grant a data frame to the *other* domain, so it can be foreign-mapped.
                let frame = FIRST_DATA + rng.below(FRAMES - FIRST_DATA);
                let grantor = (frame % u32::from(DOMAINS)) as u16;
                let grantee = 1 - grantor;
                let gref = rng.below(GRANTS);
                // A read-only grant authorizes only a read-only entry; a read-write one
                // authorizes both. Choosing here exercises both authorization paths.
                let readonly = rng.below(2) == 0;
                if hv
                    .dispatch(
                        grantor,
                        HvCall::GrantAccess {
                            gref,
                            grantee,
                            frame,
                            readonly,
                        },
                    )
                    .is_ok()
                {
                    grants.push((grantor, gref, grantee, frame));
                }
            }
            1 => {
                // Revoke a grant. A refusal here is the seam blocking revocation while a
                // foreign entry still relies on it (no grant *maps* exist in this run).
                if !grants.is_empty() {
                    let idx = rng.below(grants.len() as u32) as usize;
                    let (grantor, gref, ..) = grants[idx];
                    match hv.dispatch(grantor, HvCall::GrantEndAccess { gref }) {
                        Ok(_) => {
                            grants.swap_remove(idx);
                        }
                        Err(hv_core::HvError::Grant(grant::GrantError::InUse)) => {
                            out.revoke_blocks += 1
                        }
                        Err(_) => {}
                    }
                }
            }
            2 | 3 => {
                // Map a granted foreign frame into the grantee's table, at a seed-chosen
                // access. A writable entry over a read-only grant is refused
                // (Unauthorized); a read-only entry is authorized by any grant.
                if !grants.is_empty() {
                    let idx = rng.below(grants.len() as u32) as usize;
                    let (_grantor, _gref, grantee, frame) = grants[idx];
                    let parent = table_of(grantee);
                    let slot = rng.below(8);
                    let writable = rng.below(2) == 0;
                    match hv.dispatch(
                        grantee,
                        HvCall::P2mLink {
                            parent,
                            slot,
                            child: frame,
                            writable,
                        },
                    ) {
                        Ok(_) => {
                            out.links += 1;
                            if !writable {
                                out.ro_links += 1;
                            }
                            links.push((grantee, parent, slot));
                        }
                        Err(hv_core::HvError::Unauthorized) => out.unauthorized += 1,
                        Err(_) => {}
                    }
                }
            }
            4 => {
                // Unlink a live foreign entry.
                if !links.is_empty() {
                    let idx = rng.below(links.len() as u32) as usize;
                    let (linker, parent, slot) = links.swap_remove(idx);
                    let _ = hv.dispatch(linker, HvCall::P2mUnlink { parent, slot });
                }
            }
            _ => {
                // Attempt an *unauthorized* foreign link: map the other domain's data
                // frame with no grant behind it. Witness the isolation guard.
                let linker = rng.below(u32::from(DOMAINS)) as u16;
                let foreign = 1 - linker;
                let frame = FIRST_DATA + rng.below(FRAMES - FIRST_DATA);
                if (frame % u32::from(DOMAINS)) as u16 == foreign {
                    let slot = rng.below(8);
                    if let Err(hv_core::HvError::Unauthorized) = hv.dispatch(
                        linker,
                        HvCall::P2mLink {
                            parent: table_of(linker),
                            slot,
                            child: frame,
                            writable: true,
                        },
                    ) {
                        out.unauthorized += 1;
                    }
                }
            }
        }
        out.invariants_hold &= hv.invariants_hold();
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// The headline M1 test: across many seeds and long runs, no interleaving ever
    /// breaks the core's invariants. In a debug build the `debug_assert!` inside
    /// `dispatch` is live, so a violation panics here with the offending seed in
    /// reach. This is the "green CI in week one" the whole architecture buys.
    #[test]
    fn invariants_hold_across_many_seeds() {
        for seed in 0..10_000u64 {
            let outcome = run(seed, 256);
            // Re-assert the invariant at the boundary too, so the test still means
            // something in a release build where debug_assert is compiled out.
            assert_eq!(
                outcome.granted,
                outcome.spent + outcome.balance,
                "credit conservation violated on seed {seed}"
            );
        }
    }

    /// Determinism / seeded replay: the same seed reproduces the same run exactly.
    /// This is what turns a one-in-a-month Heisenbug into a regression test.
    #[test]
    fn same_seed_replays_identically() {
        for seed in [0u64, 1, 42, 0xB0BA, u64::MAX] {
            assert_eq!(
                run(seed, 256),
                run(seed, 256),
                "seed {seed} was not reproducible"
            );
        }
    }

    /// Sanity that the generator actually explores state — if every seed collapsed
    /// to the same outcome, the coverage above would be an illusion.
    #[test]
    fn seeds_produce_varied_outcomes() {
        let balances: BTreeSet<u64> = (0..64u64).map(|s| run(s, 256).balance).collect();
        assert!(
            balances.len() > 1,
            "scenario generator is stuck: every seed gave the same balance"
        );
    }

    /// The hand-cranked clock advances monotonically and is itself part of the
    /// replay.
    #[test]
    fn clock_is_deterministic_and_advances() {
        let a = run(7, 256);
        let b = run(7, 256);
        assert_eq!(a.ticks, b.ticks);
        assert!(a.ticks >= 256, "clock advanced at least one tick per step");
    }

    /// The M2 headline: no seeded interleaving of alloc/bind/close/send/mask ever
    /// breaks the event-channel invariants — reciprocity above all. `invariants_hold`
    /// is evaluated in release too, so this test bites regardless of build profile.
    #[test]
    fn evtchn_invariants_hold_across_many_seeds() {
        for seed in 0..10_000u64 {
            let outcome = run_evtchn(seed, 256);
            assert!(
                outcome.invariants_hold,
                "event-channel invariant violated on seed {seed}"
            );
        }
    }

    /// Seeded replay for the event-channel machine: same seed, same census exactly.
    #[test]
    fn evtchn_same_seed_replays_identically() {
        for seed in [0u64, 1, 42, 0xB0BA, u64::MAX] {
            assert_eq!(
                run_evtchn(seed, 256),
                run_evtchn(seed, 256),
                "seed {seed} was not reproducible"
            );
        }
    }

    /// The generator actually reaches interesting states — some run leaves a live
    /// interdomain link standing — otherwise the coverage above proves little.
    #[test]
    fn evtchn_seeds_reach_interdomain_bindings() {
        let any_bound = (0..256u64).any(|s| run_evtchn(s, 256).interdomain > 0);
        assert!(
            any_bound,
            "no seed ever established an interdomain binding — generator too weak"
        );
    }

    /// The grant-table headline: no seeded interleaving of grant/end/map/unmap/copy
    /// ever leaves a grant dangling or a refcount wrong — end_access-while-mapped is
    /// refused, so a mapping can never outlive its grant.
    #[test]
    fn grant_invariants_hold_across_many_seeds() {
        for seed in 0..10_000u64 {
            let outcome = run_grant(seed, 256);
            assert!(
                outcome.invariants_hold,
                "grant-table invariant violated on seed {seed}"
            );
        }
    }

    /// Seeded replay for the grant-table machine.
    #[test]
    fn grant_same_seed_replays_identically() {
        for seed in [0u64, 1, 42, 0xB0BA, u64::MAX] {
            assert_eq!(
                run_grant(seed, 256),
                run_grant(seed, 256),
                "seed {seed} was not reproducible"
            );
        }
    }

    /// The generator actually reaches live mappings — the refcount/dangling
    /// invariants only mean something once maps exist.
    #[test]
    fn grant_seeds_reach_active_maps() {
        let any_mapped = (0..256u64).any(|s| run_grant(s, 256).active_maps > 0);
        assert!(
            any_mapped,
            "no seed ever established a live mapping — generator too weak"
        );
    }

    /// The scheduler headline: no seeded interleaving of admit/run/preempt/block/
    /// wake/offline ever breaks pCPU exclusivity — no physical CPU runs two vCPUs,
    /// and the run-state and occupancy views stay perfect reciprocals.
    /// `invariants_hold` is evaluated in release too, so this bites in any profile.
    #[test]
    fn sched_invariants_hold_across_many_seeds() {
        for seed in 0..10_000u64 {
            let outcome = run_sched(seed, 256);
            assert!(
                outcome.invariants_hold,
                "scheduler invariant violated on seed {seed}"
            );
        }
    }

    /// Seeded replay for the scheduler machine: same seed, same census exactly.
    #[test]
    fn sched_same_seed_replays_identically() {
        for seed in [0u64, 1, 42, 0xB0BA, u64::MAX] {
            assert_eq!(
                run_sched(seed, 256),
                run_sched(seed, 256),
                "seed {seed} was not reproducible"
            );
        }
    }

    /// The generator actually reaches running vCPUs — the exclusivity and accounting
    /// invariants only mean something once vCPUs are on physical CPUs.
    #[test]
    fn sched_seeds_reach_running_vcpus() {
        let any_running = (0..256u64).any(|s| run_sched(s, 256).running > 0);
        assert!(
            any_running,
            "no seed ever put a vCPU on a physical CPU — generator too weak"
        );
    }

    /// Accrued runtime is monotonic in the number of steps: a longer run of the same
    /// seed shares the shorter run's prefix exactly (deterministic replay), and
    /// per-vCPU runtime only ever grows — so total runtime can never shrink.
    #[test]
    fn sched_runtime_is_monotonic_in_steps() {
        for seed in [1u64, 7, 42, 0xD1CE, u64::MAX] {
            let short = run_sched(seed, 128).total_runtime;
            let long = run_sched(seed, 256).total_runtime;
            assert!(
                long >= short,
                "seed {seed}: runtime shrank from {short} to {long} over more steps"
            );
        }
    }

    /// The page-type headline: no seeded interleaving of allocate/get/put/get_type/
    /// put_type/free ever lets a frame be referenced as writable and as a page table at
    /// once, nor lets the typed counts outrun the total — the type-confusion and
    /// coherence invariants hold throughout. `invariants_hold` is evaluated in release
    /// too, so this bites in any profile.
    #[test]
    fn p2m_invariants_hold_across_many_seeds() {
        for seed in 0..10_000u64 {
            let outcome = run_p2m(seed, 256);
            assert!(
                outcome.invariants_hold,
                "page-type invariant violated on seed {seed}"
            );
        }
    }

    /// Seeded replay for the page-type machine: same seed, same census exactly.
    #[test]
    fn p2m_same_seed_replays_identically() {
        for seed in [0u64, 1, 42, 0xB0BA, u64::MAX] {
            assert_eq!(
                run_p2m(seed, 256),
                run_p2m(seed, 256),
                "seed {seed} was not reproducible"
            );
        }
    }

    /// The generator actually reaches typed frames of *both* kinds across the seed
    /// space, and pins some — the exclusivity invariant only means something once
    /// frames are being taken writable, taken as page tables, and pinned.
    #[test]
    fn p2m_seeds_reach_both_types() {
        let outcomes: Vec<_> = (0..256u64).map(|s| run_p2m(s, 256)).collect();
        assert!(
            outcomes.iter().any(|o| o.writable_typed > 0),
            "no seed ever typed a frame writable — generator too weak"
        );
        assert!(
            outcomes.iter().any(|o| o.pagetable_typed > 0),
            "no seed ever typed a frame as a page table — generator too weak"
        );
        assert!(
            outcomes.iter().any(|o| o.pinned > 0),
            "no seed ever pinned a frame — generator too weak"
        );
    }

    /// Policy over mechanism: across many seeds of churning vCPU availability, the
    /// mechanism invariant never breaks and the policy stays work-conserving — no
    /// physical CPU idles while a vCPU is runnable. These are the policy's two headline
    /// properties, checked after every scheduling fixpoint inside `run_policy`.
    #[test]
    fn policy_is_consistent_and_work_conserving_across_seeds() {
        for seed in 0..5_000u64 {
            let outcome = run_policy(seed, 256);
            assert!(
                outcome.invariants_hold,
                "mechanism invariant broke under the policy on seed {seed}"
            );
            assert!(
                outcome.work_conserving,
                "policy left a CPU idle with a vCPU waiting on seed {seed}"
            );
        }
    }

    /// Seeded replay for the policy driver: same seed, same census exactly. The policy
    /// is a pure function of mechanism state and time, so the whole run reproduces.
    #[test]
    fn policy_same_seed_replays_identically() {
        for seed in [0u64, 1, 42, 0xB0BA, u64::MAX] {
            assert_eq!(
                run_policy(seed, 256),
                run_policy(seed, 256),
                "seed {seed} was not reproducible"
            );
        }
    }

    /// Proportional fairness: with every vCPU continuously runnable, accrued run time
    /// splits in proportion to weight. Three vCPUs weighted 1:2:3 sharing one CPU over
    /// 6000 ticks should land near 1000:2000:3000 — and strictly in weight order.
    #[test]
    fn policy_shares_cpu_in_proportion_to_weight() {
        let rt = run_policy_steady(&[1, 2, 3], 1, 1, 6000);
        let sum: u64 = rt.iter().sum();
        assert!(sum >= 5900, "the single CPU should stay busy: total {sum}");
        for (i, w) in [1u64, 2, 3].iter().enumerate() {
            let expected = 6000 * w / 6;
            let lo = expected * 9 / 10;
            let hi = expected * 11 / 10;
            assert!(
                rt[i] >= lo && rt[i] <= hi,
                "vcpu {i} (weight {w}) got {}, expected ~{expected}",
                rt[i]
            );
        }
        assert!(
            rt[0] < rt[1] && rt[1] < rt[2],
            "heavier weights must earn strictly more CPU: {rt:?}"
        );
    }

    /// No starvation: with more runnable vCPUs than CPUs and equal weights, every vCPU
    /// still earns a fair, non-trivial slice — none is left at zero. Five equal vCPUs
    /// on two CPUs over 5000 ticks should each land near 2000.
    #[test]
    fn policy_starves_no_one() {
        let rt = run_policy_steady(&[1, 1, 1, 1, 1], 2, 2, 5000);
        let min = *rt.iter().min().unwrap();
        let max = *rt.iter().max().unwrap();
        assert!(min > 0, "a vCPU was starved to zero: {rt:?}");
        // Equal weights → the spread between the most- and least-served stays tight.
        assert!(
            max - min <= max / 5,
            "equal-weight vCPUs diverged too far: {rt:?}"
        );
    }

    /// Wake-boost / sleeper fairness: a vCPU that sleeps through a long warm-up and
    /// then wakes must not monopolise the CPU to catch up on the service it missed.
    /// With wake-boost the two vCPUs share the contested CPU roughly evenly; without
    /// it, the waker starves the vCPU that stayed runnable — and turning it on visibly
    /// fixes that.
    #[test]
    fn wake_boost_keeps_a_waking_sleeper_from_starving_the_runnable() {
        const CONTEST: u64 = 2000;

        let (a_on, b_on) = run_sleeper(true);
        assert!(
            a_on >= CONTEST * 4 / 10 && b_on >= CONTEST * 4 / 10,
            "with wake-boost the contested CPU should split ~evenly: A={a_on} B={b_on}"
        );

        let (a_off, _b_off) = run_sleeper(false);
        assert!(
            a_off <= CONTEST / 10,
            "without wake-boost the always-runnable vCPU is starved: A={a_off}"
        );

        assert!(
            a_on > a_off,
            "wake-boost must materially improve the starved vCPU's share: {a_on} vs {a_off}"
        );
    }

    /// The integration headline: drive all three subsystems through the single
    /// dispatch seam for thousands of seeds, and the *combined* invariant never
    /// breaks. One check now stands in for the whole core.
    #[test]
    fn hypervisor_invariants_hold_across_many_seeds() {
        for seed in 0..10_000u64 {
            let summary = run_hypervisor(seed, 256);
            assert!(
                summary.invariants_hold,
                "integrated invariant violated on seed {seed}"
            );
        }
    }

    /// Seeded replay for the integrated core.
    #[test]
    fn hypervisor_same_seed_replays_identically() {
        for seed in [0u64, 1, 42, 0xB0BA, u64::MAX] {
            assert_eq!(
                run_hypervisor(seed, 256),
                run_hypervisor(seed, 256),
                "seed {seed} was not reproducible"
            );
        }
    }

    /// The integrated run genuinely exercises all four subsystems — across the seed
    /// space we see live interdomain links, live grant maps, non-zero balances, running
    /// vCPUs, and typed machine frames. If any stayed empty, the dispatch seam wouldn't
    /// really be covered.
    #[test]
    fn hypervisor_exercises_all_subsystems() {
        let summaries: Vec<_> = (0..256u64).map(|s| run_hypervisor(s, 256)).collect();
        assert!(
            summaries.iter().any(|s| s.interdomain > 0),
            "no seed exercised event channels"
        );
        assert!(
            summaries.iter().any(|s| s.active_maps > 0),
            "no seed exercised grant mappings"
        );
        assert!(
            summaries.iter().any(|s| s.total_balance > 0),
            "no seed exercised credit"
        );
        assert!(
            summaries.iter().any(|s| s.running > 0),
            "no seed put a vCPU on a physical CPU"
        );
        assert!(
            summaries.iter().any(|s| s.total_runtime > 0),
            "no seed accrued any scheduler runtime"
        );
        assert!(
            summaries.iter().any(|s| s.allocated_frames > 0),
            "no seed allocated a machine frame"
        );
        // A typed frame can only arise from a *writable grant map* taking a writable
        // type reference through the seam — so this reaching non-zero proves the
        // coupled grant↔page-type path is genuinely exercised, not just each alone.
        assert!(
            summaries.iter().any(|s| s.typed_frames > 0),
            "no seed pinned a frame's type via a writable grant map"
        );
        // Page-table typing arrives only through pin (MMUEXT_PIN_TABLE) — reaching it
        // proves the guest can now produce the *other* half of the write-xor conflict.
        assert!(
            summaries.iter().any(|s| s.pinned_frames > 0),
            "no seed pinned a frame as a page table"
        );
    }

    /// The event↔scheduler seam headline: across many seeds of blocking, signalling,
    /// masking, and churning the *same* vCPUs, the integrated invariant — no deliverable
    /// event ever resting on a `Blocked` vCPU — holds after every single step, not just
    /// at the end. This is the seam's soundness under interleaving, with the seed as the
    /// whole reproducer.
    #[test]
    fn seam_invariant_holds_across_many_seeds() {
        for seed in 0..10_000u64 {
            assert!(
                run_seam(seed, 256).invariants_hold,
                "event↔scheduler invariant violated on seed {seed}"
            );
        }
    }

    /// Seeded replay for the seam driver: same seed, same observed counts exactly.
    #[test]
    fn seam_same_seed_replays_identically() {
        for seed in [0u64, 1, 42, 0xB0BA, u64::MAX] {
            assert_eq!(
                run_seam(seed, 256),
                run_seam(seed, 256),
                "seed {seed} was not reproducible"
            );
        }
    }

    /// The driver genuinely exercises the seam, not just the invariant: across the seed
    /// space some run actually wakes a `Blocked` vCPU through a send/unmask, and some run
    /// hits the block-race no-op (a vCPU declining to sleep on a deliverable event). If
    /// either stayed zero, the invariant above would be proving the seam over states the
    /// seam never reaches.
    #[test]
    fn seam_actually_fires_both_paths() {
        let outcomes: Vec<_> = (0..256u64).map(|s| run_seam(s, 256)).collect();
        assert!(
            outcomes.iter().any(|o| o.wakes > 0),
            "no seed ever woke a blocked vCPU through the seam — driver too weak"
        );
        assert!(
            outcomes.iter().any(|o| o.block_noops > 0),
            "no seed ever hit the block-with-pending-event no-op — driver too weak"
        );
    }

    /// The domain-teardown headline: across many seeds of building domains up and
    /// tearing them down mid-flight, the integrated invariant holds after every step
    /// *and* every destroy obeys its contract — refused exactly when a foreign map
    /// stood, and otherwise leaving a proper empty shell. Teardown welds all four
    /// subsystems and both seams, so this is the whole net biting at once.
    #[test]
    fn destroy_is_sound_and_keeps_its_contract_across_seeds() {
        for seed in 0..10_000u64 {
            let out = run_destroy(seed, 256);
            assert!(
                out.invariants_hold,
                "integrated invariant violated under teardown on seed {seed}"
            );
            assert!(
                out.postcondition_held,
                "a destroy broke its precondition/postcondition contract on seed {seed}"
            );
        }
    }

    /// Seeded replay for the teardown driver: same seed, same observed outcome exactly.
    #[test]
    fn destroy_same_seed_replays_identically() {
        for seed in [0u64, 1, 42, 0xB0BA, u64::MAX] {
            assert_eq!(
                run_destroy(seed, 256),
                run_destroy(seed, 256),
                "seed {seed} was not reproducible"
            );
        }
    }

    /// The driver genuinely reaches *both* teardown paths across the seed space: some
    /// run refuses a destroy because a foreign domain holds a live map (`DomainBusy`),
    /// and some run tears a domain down cleanly. If either stayed zero, the soundness
    /// test above would be proving teardown over a path it never actually takes.
    #[test]
    fn destroy_reaches_both_the_busy_and_clean_paths() {
        let outcomes: Vec<_> = (0..256u64).map(|s| run_destroy(s, 256)).collect();
        assert!(
            outcomes.iter().any(|o| o.teardowns > 0),
            "no seed ever tore a domain down — driver too weak"
        );
        assert!(
            outcomes.iter().any(|o| o.busy_refusals > 0),
            "no seed ever hit a busy-refusal — the refuse-if-busy path is uncovered"
        );
    }

    /// The multi-level page-table headline: no seeded interleaving of allocate/pin/link/
    /// unlink/free ever breaks the page invariants — including the hierarchy, that every
    /// live entry points exactly one paging level down. `invariants_hold` is evaluated in
    /// release too, so this bites in any profile.
    #[test]
    fn ptab_invariants_hold_across_many_seeds() {
        for seed in 0..10_000u64 {
            assert!(
                run_ptab(seed, 256).invariants_hold,
                "page-table hierarchy invariant violated on seed {seed}"
            );
        }
    }

    /// Seeded replay for the page-table driver: same seed, same census exactly.
    #[test]
    fn ptab_same_seed_replays_identically() {
        for seed in [0u64, 1, 42, 0xB0BA, u64::MAX] {
            assert_eq!(
                run_ptab(seed, 256),
                run_ptab(seed, 256),
                "seed {seed} was not reproducible"
            );
        }
    }

    /// The driver genuinely reaches real depth across the seed space: tables appear at
    /// *every* level and ordinary leaves under L1s, and some run stands up a live edge.
    /// If a level never appeared, the hierarchy invariant above would be proving itself
    /// over trees the driver never actually builds.
    #[test]
    fn ptab_reaches_every_level() {
        let outcomes: Vec<_> = (0..512u64).map(|s| run_ptab(s, 256)).collect();
        for (name, reached) in [
            ("L4", outcomes.iter().any(|o| o.l4 > 0)),
            ("L3", outcomes.iter().any(|o| o.l3 > 0)),
            ("L2", outcomes.iter().any(|o| o.l2 > 0)),
            ("L1", outcomes.iter().any(|o| o.l1 > 0)),
            ("leaf", outcomes.iter().any(|o| o.leaves > 0)),
            ("edge", outcomes.iter().any(|o| o.active_links > 0)),
            // The read-only leaf onto a live page table — the linear-map coexistence.
            // Without this, the loosened invariant would be proving itself over a case
            // the driver never actually reaches.
            (
                "ro-onto-pagetable",
                outcomes.iter().any(|o| o.ro_onto_pagetable > 0),
            ),
        ] {
            assert!(reached, "no seed ever produced a {name} — driver too weak");
        }
    }

    /// The cross-domain headline: no seeded interleaving of granting, foreign-mapping,
    /// unlinking, and revoking ever leaves an unauthorized cross-domain page-table entry
    /// standing — the isolation invariant holds after every step across the seed space.
    #[test]
    fn foreign_authorization_holds_across_many_seeds() {
        for seed in 0..10_000u64 {
            assert!(
                run_foreign(seed, 256).invariants_hold,
                "foreign-link authorization invariant violated on seed {seed}"
            );
        }
    }

    /// Seeded replay for the cross-domain driver: same seed, same observed counts exactly.
    #[test]
    fn foreign_same_seed_replays_identically() {
        for seed in [0u64, 1, 42, 0xB0BA, u64::MAX] {
            assert_eq!(
                run_foreign(seed, 256),
                run_foreign(seed, 256),
                "seed {seed} was not reproducible"
            );
        }
    }

    /// The driver genuinely reaches each path across the seed space: some run installs a
    /// live cross-domain entry, some run is refused for want of a grant, and some run
    /// blocks a revoke because a foreign entry still relies on the grant. If any stayed
    /// zero, the invariant above would be proving isolation over states never reached.
    #[test]
    fn foreign_reaches_authorized_unauthorized_and_revoke_block() {
        let outcomes: Vec<_> = (0..256u64).map(|s| run_foreign(s, 256)).collect();
        assert!(
            outcomes.iter().any(|o| o.links > 0),
            "no seed ever installed a cross-domain entry — driver too weak"
        );
        assert!(
            outcomes.iter().any(|o| o.ro_links > 0),
            "no seed ever installed a read-only cross-domain entry — the RO path is uncovered"
        );
        assert!(
            outcomes.iter().any(|o| o.unauthorized > 0),
            "no seed ever hit the unauthorized refusal — the isolation guard is uncovered"
        );
        assert!(
            outcomes.iter().any(|o| o.revoke_blocks > 0),
            "no seed ever blocked a revoke under a live foreign entry — path uncovered"
        );
    }
}
