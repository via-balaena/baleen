// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Deterministic simulation.
//!
//! A `u64` seed drives a reproducible sequence of hypercalls and clock advances
//! through [`hv_core::HvCore`]. The core's `debug_assert!` invariants fire on every
//! transition, so a violation surfaces here — and the seed that produced it is the
//! whole reproducer. This is the FoundationDB discipline shrunk to a laptop.

use hv_core::evtchn::{PortState, System};
use hv_core::{prng::Prng, HvCore, Hypercall};
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
}
