// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Deterministic simulation.
//!
//! A `u64` seed drives a reproducible sequence of hypercalls and clock advances
//! through [`hv_core::HvCore`]. The core's `debug_assert!` invariants fire on every
//! transition, so a violation surfaces here — and the seed that produced it is the
//! whole reproducer. This is the FoundationDB discipline shrunk to a laptop.

use hv_core::evtchn::{PortState, System};
use hv_core::{grant, prng::Prng, sched, HvCall, HvCore, HvOutcome, Hypercall, Hypervisor};
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
                let frame = u64::from(rng.below(64));
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
        s.invariants_hold = hv.invariants_hold();
        s
    }
}

/// Drive the whole integrated [`Hypervisor`] through a seed-derived stream of typed
/// hypercalls across all three subsystems, tracking live grant handles so unmaps go
/// to their owners. One loop exercises credit, event channels, and grant tables
/// through the single dispatch seam; one invariant check covers the lot.
pub fn run_hypervisor(seed: u64, steps: u32) -> HvSummary {
    const DOMAINS: u16 = 3;
    const PORTS: u32 = 8;
    const GRANTS: u32 = 6;
    const VCPUS: u32 = 2;
    const PCPUS: u32 = 2;

    let mut hv = Hypervisor::new(
        DOMAINS as usize,
        PORTS as usize,
        GRANTS as usize,
        VCPUS as usize,
        PCPUS as usize,
    );
    let mut rng = Prng::new(seed);
    let clock = ManualClock::new();
    let mut handles: Vec<(u16, u32)> = Vec::new(); // (grantee/owner, handle) of live maps

    for _ in 0..steps {
        // Crank the clock so scheduler run/preempt intervals span seed-derived gaps.
        clock.advance(1 + u64::from(rng.below(16)));
        let now = clock.now();

        let caller = rng.below(u32::from(DOMAINS)) as u16;
        let port = rng.below(PORTS);
        let gref = rng.below(GRANTS);
        let vcpu = rng.below(VCPUS);
        let pcpu = rng.below(PCPUS);

        match rng.below(21) {
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
                let grantee = rng.below(u32::from(DOMAINS)) as u16;
                drop_ok(hv.dispatch(
                    caller,
                    HvCall::GrantAccess {
                        gref,
                        grantee,
                        frame: u64::from(rng.below(64)),
                        readonly: rng.below(2) == 0,
                    },
                ));
            }
            11 => drop_ok(hv.dispatch(caller, HvCall::GrantEndAccess { gref })),
            12 => {
                let grantor = rng.below(u32::from(DOMAINS)) as u16;
                // The caller maps, so the caller owns the resulting handle.
                if let Ok(HvOutcome::Handle(h)) = hv.dispatch(
                    caller,
                    HvCall::GrantMap {
                        grantor,
                        gref,
                        writable: rng.below(2) == 0,
                    },
                ) {
                    handles.push((caller, h));
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
            _ => drop_ok(hv.dispatch(caller, HvCall::SchedOffline { vcpu, now })),
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

    /// The integrated run genuinely exercises all three subsystems — across the seed
    /// space we see live interdomain links, live grant maps, and non-zero balances.
    /// If any stayed empty, the dispatch seam wouldn't really be covered.
    #[test]
    fn hypervisor_exercises_all_three_subsystems() {
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
    }
}
