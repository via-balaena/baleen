// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Deterministic simulation.
//!
//! A `u64` seed drives a reproducible sequence of hypercalls and clock advances
//! through [`hv_core::HvCore`]. The core's `debug_assert!` invariants fire on every
//! transition, so a violation surfaces here — and the seed that produced it is the
//! whole reproducer. This is the FoundationDB discipline shrunk to a laptop.

use hv_core::evtchn::{PortState, System};
use hv_core::p2m::PageType;
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
                    Some(PageType::PageTable) => o.pagetable_typed += 1,
                    None => {}
                }
            }
        }
        o.invariants_hold = sys.invariants_hold();
        o
    }
}

/// Drive the page-type [`p2m::System`] through a seed-derived stream of allocate / get
/// / put / get_type / put_type / free operations across a few domains and frames,
/// tracking live typed references so put_type targets a type the frame actually holds.
/// Same discipline as the others: the core's `debug_assert!` fires on every transition,
/// so a broken writable-xor-pagetable exclusivity surfaces here with the seed as the
/// whole reproducer. This is where a page racing between writable and page-table use —
/// the shape of Xen's `PGT_*` typecount XSAs — is stress-tested.
pub fn run_p2m(seed: u64, steps: u32) -> P2mOutcome {
    const DOMAINS: u16 = 3;
    const FRAMES: u32 = 6;

    let mut sys = p2m::System::new(DOMAINS as usize, FRAMES as usize);
    let mut rng = Prng::new(seed);
    let mut typed: Vec<(u32, PageType)> = Vec::new(); // (mfn, type) of live typed refs

    for _ in 0..steps {
        let owner = rng.below(u32::from(DOMAINS)) as u16;
        let mfn = rng.below(FRAMES);
        match rng.below(7) {
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
                    PageType::PageTable
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

        match rng.below(23) {
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
            _ => drop_ok(hv.dispatch(caller, HvCall::P2mFree { mfn })),
        }
    }

    HvSummary::of(&hv)
}

/// Discard a dispatch result — many calls fail by design (spend beyond balance,
/// send on a free port), and that is part of what the sim exercises.
fn drop_ok(result: Result<HvOutcome, hv_core::HvError>) {
    let _ = result;
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
    /// space — the exclusivity invariant only means something once frames are being
    /// pinned as writable and as page tables.
    #[test]
    fn p2m_seeds_reach_both_types() {
        let outcomes: Vec<_> = (0..256u64).map(|s| run_p2m(s, 256)).collect();
        assert!(
            outcomes.iter().any(|o| o.writable_typed > 0),
            "no seed ever pinned a frame writable — generator too weak"
        );
        assert!(
            outcomes.iter().any(|o| o.pagetable_typed > 0),
            "no seed ever pinned a frame as a page table — generator too weak"
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
    }
}
