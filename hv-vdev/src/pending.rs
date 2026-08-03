// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The per-vCPU **software pending set**'s index algebra, under the fence
//!
//! ## What a pending set is for
//!
//! A GICv3 CPU interface has a small, fixed number of list registers — **four** on QEMU `virt`. When
//! EL2 wants to make a virtual interrupt pending and every list register is occupied, it has three
//! choices: drop the interrupt (a guest that stops scheduling), halt (loud, but a hypervisor that a
//! guest can stop by asking for interrupts), or **remember it and deliver it when the bank runs
//! down**. III-1 chose the third, and the memory is a per-vCPU *set* rather than a queue for a
//! precise reason: **a queue's "full" is the old halt relocated**, while a set over every INTID the
//! guest can name has no "full" state at all. Overflow stops being handled and becomes
//! unrepresentable.
//!
//! That argument only holds if the set really does cover every INTID the guest can name. **This
//! module is the arithmetic that decides whether it does**, and the arithmetic is where it can go
//! wrong silently.
//!
//! ## The defect this exists to make impossible
//!
//! `hv-metal`'s original set indexed a fixed four-word array with `intid / 64`. Four words is 256
//! bits, which was correct *because every caller first narrowed the INTID through a `u8` HAL fence*.
//! Nothing in the indexing said so. An INTID of 256 or more computes word index 4 into a
//! four-element array — **an out-of-bounds index inside EL2's asynchronous interrupt path**, which is
//! about the worst place in the system to put a panic.
//!
//! It was never reachable, and the reason it was never reachable lived in a different file, in a cast
//! at each call site. The emulated distributor advertises **288** INTIDs, so the moment a path
//! without that cast marks an interrupt the guest legitimately owns, the bound is wrong.
//!
//! So the capacity relationship is stated here as a theorem — [`word_of`] lands inside
//! [`words_for`]`(n)` for every INTID below `n` — and the deployment pins its own array to
//! `words_for(NUM_INTIDS)` with a `const assert!`. The bound stops being a comment about what callers
//! promise to do.
//!
//! ## What is here and what is not — ⑯'s split again
//!
//! **Here: the index arithmetic.** Which word, which bit, which INTID a set bit denotes, and how to
//! find the lowest one. Pure functions of integers.
//!
//! **Not here: the storage.** The metal keeps the set in `AtomicU64`s, because injection is reachable
//! from the asynchronous EL2 exception path and a read-modify-write must not be split by an interrupt
//! arriving between the load and the store. Atomicity is a property of the *machine*, not of the
//! arithmetic — and a pure model that pretended to it would be modelling the one thing it cannot
//! check. The metal does `fetch_or(bit_of(i))` on `words[word_of(i)]`: the atomicity is its own, the
//! arithmetic is this module's, and there is exactly one derivation of the arithmetic.

/// How many `u64` words are needed to hold `intids` bits.
///
/// Ceiling division. `usize::div_ceil` is `const` on the pinned MSRV — the `MSRV (1.96)` job is what
/// keeps that true, and it is a required check, so a toolchain floor that lost it fails there rather
/// than here.
pub const fn words_for(intids: usize) -> usize {
    intids.div_ceil(64)
}

/// Which word of a pending set holds `intid`'s bit.
pub const fn word_of(intid: u32) -> usize {
    (intid as usize) / 64
}

/// A mask with exactly `intid`'s bit set, within its word.
pub const fn bit_of(intid: u32) -> u64 {
    1u64 << ((intid as usize) % 64)
}

/// The INTID denoted by bit `bit` of word `word` — the inverse of [`word_of`] + [`bit_of`].
pub const fn intid_of(word: usize, bit: u32) -> u32 {
    (word * 64) as u32 + bit
}

/// The **lowest-numbered** INTID whose bit is set, or [`None`] if none is.
///
/// **Lowest-first is not an ordering promise** — a set has no order. It is chosen because the GIC
/// itself resolves simultaneous pending interrupts by priority and, at equal priority, by lowest
/// INTID, so draining in this order makes the software half agree with the hardware half's tie-break.
///
/// Takes the words rather than a set type because the metal's live copy is an array of atomics it
/// must load itself; this is the arithmetic applied to what it loaded.
pub fn lowest_set(words: &[u64]) -> Option<u32> {
    let mut w = 0;
    while w < words.len() {
        if words[w] != 0 {
            return Some(intid_of(w, words[w].trailing_zeros()));
        }
        w += 1;
    }
    None
}

/// Whether every word is zero — the set is empty.
///
/// The metal drives its `UIE` arming from this, so it is the same question asked of the same bits
/// rather than a second notion of emptiness.
pub fn is_empty(words: &[u64]) -> bool {
    let mut w = 0;
    while w < words.len() {
        if words[w] != 0 {
            return false;
        }
        w += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capacity_bound_is_what_the_old_fixed_four_words_got_wrong() {
        // 288 INTIDs — what the emulated distributor advertises — needs FIVE words, not four.
        assert_eq!(words_for(288), 5);
        assert_eq!(words_for(256), 4);
        // The INTID that used to index one past the end of a four-word array.
        assert_eq!(word_of(256), 4);
    }

    #[test]
    fn a_bit_round_trips_through_the_index_arithmetic() {
        for intid in [0u32, 1, 63, 64, 65, 255, 256, 287] {
            let w = word_of(intid);
            let b = bit_of(intid).trailing_zeros();
            assert_eq!(intid_of(w, b), intid);
        }
    }

    #[test]
    fn lowest_set_finds_the_minimum_across_a_word_boundary() {
        let mut words = [0u64; 5];
        words[1] |= bit_of(70);
        words[0] |= bit_of(9);
        assert_eq!(lowest_set(&words), Some(9));
        words[0] = 0;
        assert_eq!(lowest_set(&words), Some(70));
        words[1] = 0;
        assert_eq!(lowest_set(&words), None);
        assert!(is_empty(&words));
    }
}
