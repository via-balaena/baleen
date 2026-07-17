// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! A tiny, dependency-free, fully deterministic PRNG (xorshift64).
//!
//! Determinism is the whole point: a `u64` seed reproduces an entire scenario, so
//! a Heisenbug found on a 64-core box in a month becomes a one-line regression
//! test on your laptop. This lives in `hv-core` (not the harness) so that on-target
//! and simulated code can share the exact same event stream.

/// A seeded xorshift64 generator. Identical seeds yield identical sequences, and
/// *distinct* seeds yield distinct sequences (see [`Prng::new`]).
#[derive(Debug, Clone)]
pub struct Prng {
    state: u64,
}

/// The golden-ratio mixing constant — also the state seed `0` maps to.
const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;

impl Prng {
    /// Create a generator from `seed`. Xorshift requires a nonzero state, so the seed
    /// is mixed with the golden ratio (a bijection — distinct seeds give distinct
    /// states) and the lone seed that mixes to zero is redirected to `GOLDEN`. The map
    /// is thus injective and nonzero for every seed but one: `seed == GOLDEN` shares
    /// `seed == 0`'s state, a single collision no scenario sweep reaches.
    ///
    /// A prior version forced the low bit set (`… | 1`), which erased seed bit 0 and
    /// collapsed every consecutive seed pair `(2k, 2k+1)` onto one sequence — silently
    /// halving the coverage of every seed sweep. Do not reintroduce that.
    pub fn new(seed: u64) -> Self {
        let mixed = seed ^ GOLDEN;
        Prng {
            state: if mixed == 0 { GOLDEN } else { mixed },
        }
    }

    /// Next raw 64-bit value.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    /// A value in `0..n`. Panics if `n == 0`.
    pub fn below(&mut self, n: u32) -> u32 {
        assert!(n != 0, "Prng::below(0) has no valid output");
        (self.next_u64() % n as u64) as u32
    }
}

#[cfg(test)]
mod tests {
    use super::Prng;

    #[test]
    fn same_seed_same_sequence() {
        let mut a = Prng::new(42);
        let mut b = Prng::new(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn seed_zero_is_not_stuck() {
        let mut p = Prng::new(0);
        // A zero internal state would return 0 forever; verify it moves.
        assert_ne!(p.next_u64(), 0);
        assert_ne!(p.next_u64(), p.next_u64());
    }

    #[test]
    fn below_stays_in_range() {
        let mut p = Prng::new(7);
        for _ in 0..10_000 {
            assert!(p.below(10) < 10);
        }
    }

    // Distinct seeds must give distinct streams — regression for a mixing bug that
    // forced the low bit set and collapsed every (2k, 2k+1) seed pair onto one sequence,
    // silently halving the coverage of every seed sweep. Consecutive seeds are the
    // sharpest probe (they differ only in bit 0, the bit the bug erased), and the sweeps
    // run `0..N`, so check a dense prefix pairwise.
    #[test]
    fn consecutive_seeds_give_distinct_streams() {
        // The exact reported collision first.
        assert_ne!(Prng::new(0).next_u64(), Prng::new(1).next_u64());
        for k in 0..4096u64 {
            assert_ne!(
                Prng::new(2 * k).next_u64(),
                Prng::new(2 * k + 1).next_u64(),
                "seeds {} and {} produced the same stream",
                2 * k,
                2 * k + 1
            );
        }
    }
}
