// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The per-vCPU software pending set — **one type, both switches**
//!
//! ## Why this file exists rather than a second copy of III-1's set
//!
//! III-1 gave the synthetic path a per-vCPU pending set so that a full list-register bank stopped
//! halting the hypervisor. The real-Linux path never got one, and it is the path that now carries the
//! isolation thesis. Writing a second set for it would be the **second-derivation defect** this
//! project has spent three rungs removing — `gic::VgicCtx` (one answer to "what is a vGIC context"),
//! `fp::FpCtx` (one answer to "what is an FP context"), and ⑰-b′ (one answer to "what do the list
//! register's bits mean"). So there is one answer to "what is a pending set", and both switches use
//! it.
//!
//! ## The split, and the part that is deliberately not here
//!
//! **The arithmetic is [`hv_vdev::pending`]** — which word, which bit, which INTID a set bit denotes,
//! and how to find the lowest. It is pure, so Kani proves it, and the proof that matters is the
//! capacity one: `word_of(intid)` lands inside the array for every INTID the distributor can name.
//! That bound used to be a convention enforced by `as u8` casts in a different file (see below).
//!
//! **The atomicity is here**, because it is a property of the machine rather than of the arithmetic.
//! Injection is reachable from the asynchronous EL2 exception path, so a read-modify-write must not be
//! split by an interrupt landing between the load and the store. A pure model that pretended to
//! atomicity would be modelling the one thing it cannot check.
//!
//! ## ★ The sizing, which is a safety property and not a tidiness one
//!
//! III-1's set was **four** words — 256 bits — and its own comment says why: *"the whole range the
//! `u8` HAL fence can express"*. That is correct for the synthetic path, whose every injection passes
//! through `VcpuOps::inject_interrupt(vector: u8)`.
//!
//! **The real-Linux path has no such fence** — it calls `gic::inject`/`gic::inject_hw` directly — and
//! the emulated distributor advertises **288** INTIDs. Indexing a four-word array with `intid / 64`
//! for an INTID of 256 or more is an **out-of-bounds index inside EL2's interrupt path**. It was
//! never reachable, and the reason it was never reachable lived in a cast at each call site rather
//! than in the set.
//!
//! So the capacity here is derived from the distributor's own INTID count, and
//! `hv-verify`'s `the_word_index_of_any_nameable_intid_is_in_range` proves the relationship holds.
//! Both paths get the same width: the synthetic path never names an INTID above 255, so the extra
//! word costs it 8 bytes per vCPU and removes a divergence that would otherwise have to be remembered.

use core::sync::atomic::{AtomicU64, Ordering};

use hv_vdev::gicv3::NUM_INTIDS;
use hv_vdev::pending::{bit_of, is_empty, lowest_set, word_of, words_for};

/// `u64` words in a pending set — sized to the **emulated distributor's** INTID space, not to a
/// fence that only one of the two paths has.
pub(crate) const PENDING_WORDS: usize = words_for(NUM_INTIDS);

/// The distributor's whole INTID space must fit, or a guest could make an interrupt pending that the
/// set cannot represent. Proven in general by `hv-verify`; pinned to *this* deployment here, which is
/// the split ⑯ established for a claim that binds a model to a board.
const _: () = assert!(
    PENDING_WORDS * 64 >= NUM_INTIDS,
    "the pending set must cover every INTID the emulated distributor can name"
);

/// A vCPU's **software pending set**: bit `i` of word `w` = vINTID `w * 64 + i` is pending for that
/// vCPU but has no list register yet.
///
/// A **set**, not a queue, and that is the whole argument: a queue's "full" is the old halt relocated,
/// while a set over every nameable INTID has no full state at all. Marking is idempotent because an
/// interrupt asserted twice before the guest takes it once is still one pending interrupt.
pub(crate) struct PendingSet {
    words: [AtomicU64; PENDING_WORDS],
}

/// **A pending set belongs to ONE vCPU.** III-1 established this on the synthetic path — its own
/// reasoning is that a shared set "would reopen the cross-vCPU leak 8b/III-3 closed" — and until
/// ⑱-3a the real-Linux path's `LINUX_PENDING` was per-GUEST, which at one vCPU per guest is the same
/// arrangement by coincidence. Declaring only `PerVcpuState` makes that coincidence a build error.
///
/// `cfg`-gated because `crate::role` is: the synthetic path indexes its own `VCPU_PENDING` array
/// directly and has no `PerVcpu`, so there is no container for this claim to constrain there. ⑭'s
/// rule — say which configuration an item belongs to, rather than `allow(dead_code)` over it.
#[cfg(feature = "real-linux")]
impl crate::role::PerVcpuState for PendingSet {}

impl PendingSet {
    /// An empty set.
    ///
    /// A `const fn` rather than an associated `const`, because a named constant holding an
    /// `AtomicU64` is a clippy `declare_interior_mutable_const` error — each *use* of such a constant
    /// would be a fresh value, which is exactly wrong for a shared set. Callers write
    /// `[const { PendingSet::new() }; N]`, where the inline-const is evaluated once per element.
    pub(crate) const fn new() -> Self {
        Self {
            words: [const { AtomicU64::new(0) }; PENDING_WORDS],
        }
    }

    /// Record `intid` as pending. Idempotent.
    ///
    /// Returns `false` — recording nothing — if `intid` is outside the distributor's INTID space.
    /// **No caller can currently produce one**: the forwarded timer is a `const` below `NUM_INTIDS`
    /// (`gic`'s `const assert!`), and a guest SGI comes from a four-bit field so it is at most 15.
    /// The case is refused rather than masked because masking would make one interrupt arrive as a
    /// *different* one, which is the same class of silent error ⑰-b′ removed from the `pINTID` field.
    #[must_use]
    pub(crate) fn mark(&self, intid: u32) -> bool {
        if (intid as usize) >= NUM_INTIDS {
            return false;
        }
        self.words[word_of(intid)].fetch_or(bit_of(intid), Ordering::Relaxed);
        true
    }

    /// Whether anything is waiting for a list register.
    ///
    /// The `UIE` arming is driven from exactly this, so "is there anything to refill with" is one
    /// question asked of one set of bits rather than two notions that can disagree.
    pub(crate) fn is_empty(&self) -> bool {
        let snapshot = self.snapshot();
        is_empty(&snapshot)
    }

    /// Remove and return the **lowest-numbered** pending vINTID, if any.
    ///
    /// Lowest-first is not an ordering promise — a set has no order. It matches the GIC's own
    /// tie-break (priority, then lowest INTID), so the software half drains in the order the hardware
    /// half would have resolved.
    pub(crate) fn take_next(&self) -> Option<u32> {
        let snapshot = self.snapshot();
        let intid = lowest_set(&snapshot)?;
        self.words[word_of(intid)].fetch_and(!bit_of(intid), Ordering::Relaxed);
        Some(intid)
    }

    /// Clear the whole set. (`selftest`-only: the real paths only ever *drain* through
    /// `take_next`, which is what keeps the `UIE` arming consistent with what remains — a bulk clear
    /// needs its own re-arm, so the witness pairs every call with one.)
    #[cfg(feature = "selftest")]
    pub(crate) fn clear(&self) {
        for w in &self.words {
            w.store(0, Ordering::Relaxed);
        }
    }

    /// Load every word once, so the pure arithmetic sees one consistent picture.
    fn snapshot(&self) -> [u64; PENDING_WORDS] {
        let mut out = [0u64; PENDING_WORDS];
        for (slot, word) in out.iter_mut().zip(self.words.iter()) {
            *slot = word.load(Ordering::Relaxed);
        }
        out
    }
}
