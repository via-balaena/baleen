// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! A tiny, dependency-free, fully deterministic PRNG (xorshift64).
//!
//! Determinism is the whole point: a `u64` seed reproduces an entire scenario, so
//! a Heisenbug found on a 64-core box in a month becomes a one-line regression
//! test on your laptop. This lives in `hv-core` (not the harness) so that on-target
//! and simulated code can share the exact same event stream.

/// A seeded xorshift64 generator. Identical seeds yield identical sequences.
#[derive(Debug, Clone)]
pub struct Prng {
    state: u64,
}

impl Prng {
    /// Create a generator from `seed`. Every seed — including `0` — maps to a
    /// distinct, nonzero internal state (xorshift requires nonzero state).
    pub fn new(seed: u64) -> Self {
        // Mix with the golden ratio and force a set bit so state is never zero.
        Prng {
            state: (seed ^ 0x9E37_79B9_7F4A_7C15) | 1,
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
}
