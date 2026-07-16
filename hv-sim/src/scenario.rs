// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Deterministic simulation.
//!
//! A `u64` seed drives a reproducible sequence of hypercalls and clock advances
//! through [`hv_core::HvCore`]. The core's `debug_assert!` invariants fire on every
//! transition, so a violation surfaces here — and the seed that produced it is the
//! whole reproducer. This is the FoundationDB discipline shrunk to a laptop.

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
}
