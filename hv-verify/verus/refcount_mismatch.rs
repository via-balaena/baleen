// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Tier C / Verus — `RefcountMismatch` preservation, ∀ table size
//!
//! This is the **Verus phase** of Tier C: the genuine ∀-N step the Kani spike could not take.
//! Kani (`hv-verify/src/lib.rs`) made the grant refcounts symbolic and proved
//! `WritableExceedsMaps` preserved for **all 2³² magnitudes** on the *real* `hv-core` code —
//! but it stays bounded on the `Vec` *length* (Kani would have to `unwind` the mapping table).
//! `RefcountMismatch` is precisely the invariant that couples a scalar to that `Vec` length —
//!
//! > **`RefcountMismatch`** (`hv-core/src/grant.rs`, `first_violation`): for every active grant
//! > entry `(d,g)`, the recorded scalars equal the cardinality of a *filtered subsequence* of
//! > the global live-mapping table:
//! >   `maps          == |{ live m : m.grantor==d ∧ m.gref==g }|`
//! >   `writable_maps == |{ live m : m.grantor==d ∧ m.gref==g ∧ m.writable }|`
//!
//! — so proving *it* preserved for an **arbitrary-length** table is the arbitrary-size result,
//! and it is what discharges (for all sizes) the two `kani::assume`s the spike's unmap harness
//! could only assert (`maps ≥ 1`, and read-only ⇒ `writable_maps ≤ maps−1`). See
//! `docs/TIER-C-SPIKE.md` §3–4 and `docs/TIER-B-CUTOFF.md` §1.4/§3(1).
//!
//! ## Why this is a mirror, and how fidelity is managed
//!
//! Verus is its own Rust *dialect* — `spec fn`/`requires`/`ensures`/`verus!{}` do not parse
//! under stable `rustc`, and Verus must front-end the *entire* crate it verifies (it cannot be
//! `#[cfg]`-hidden the way Kani harnesses — ordinary Rust — are). Verifying `hv-core` in place
//! would therefore break `cargo build`/`cargo test --workspace`/MSRV/clippy for the whole
//! shipping brain. So the transition is **mirrored** here, in the Verus subset, and `hv-core`
//! stays pristine and stable-buildable. This file lives *outside* `hv-verify/src/`, so cargo
//! never compiles it; it is verified out-of-band by `verus --crate-type=lib` (see the
//! `verus` job in `.github/workflows/deep-verify.yml` and `hv-verify/verus/README.md`).
//!
//! A mirror only proves something about shipped code if it faithfully *is* the shipped
//! transition. Three anchors, documented inline below:
//!   1. **Shared arithmetic, transcribed.** [`counts_after_map`]/[`counts_after_unmap`] here
//!      transcribe `hv_core::grant::System::counts_after_map`/`counts_after_unmap` expression
//!      for expression (design-lesson #14c — those were already factored out so production and
//!      the Kani proof share one definition; this is the third consumer).
//!   2. **The predicate mirrors `first_violation`.** [`matches`]/[`count`] are exactly the
//!      per-entry filter+count `first_violation` runs.
//!   3. **The enumerator pins fidelity on the real code at small size.** `hv-sim::enumerate`
//!      exhaustively checks `RefcountMismatch` on the *actual* `System` for small configs and
//!      finds nothing; Kani checks the ∀-magnitude axis on real code. This file adds the
//!      ∀-length axis on the mirror — the three cover complementary axes of one obligation.
//!
//! ## Non-vacuity (validated, not asserted)
//!
//! Perturbing the arithmetic makes Verus reject the proof — the analog of the enumerator's
//! "remove the fix → counterexample". Verified by hand during the spike (see the commit /
//! `hv-verify/verus/README.md`): claim `map` leaves `maps` unchanged, or drop the writable
//! bump, or make `unmap` not decrement — each yields "postcondition not satisfied".
//!
//! Run: `verus --crate-type=lib hv-verify/verus/refcount_mismatch.rs` (exit 0 = all proven).

use vstd::prelude::*;

verus! {

/// One live mapping — the grantee's side of an active grant. Mirror of
/// `hv_core::grant::Mapping`, projected to exactly the fields `RefcountMismatch` reads
/// (`active`, `grantor`, `gref`, `writable`; the real struct also carries `grantee`, which no
/// refcount predicate reads). ids are `nat` (the reduction of §2.1: only sizes matter, ids are
/// compared structurally — so unbounded `nat` is the honest ∀-size domain).
struct Mapping {
    active: bool,
    grantor: nat,
    gref: nat,
    writable: bool,
}

/// `if b { 1 } else { 0 }` as a `nat` — a count contribution.
spec fn b2n(b: bool) -> nat {
    if b { 1 } else { 0 }
}

/// Does mapping `m` count toward entry `(d,g)`'s refcount? `rw == false` selects the `maps`
/// count, `rw == true` the `writable_maps` count. This is exactly the filter in
/// `first_violation` (`grant.rs`): `m.active && m.grantor as usize == d && m.gref as usize == g`
/// (and, for `writable_maps`, `m.writable`).
spec fn matches(m: Mapping, d: nat, g: nat, rw: bool) -> bool {
    m.active && m.grantor == d && m.gref == g && (!rw || m.writable)
}

/// `|{ live mappings matching (d,g,rw) }|` over the whole mapping table — the cardinality
/// `RefcountMismatch` pins the scalar counter to (`first_violation`'s `live.count()` /
/// `live.filter(writable).count()`). Recurses peeling the **last** element so the induction
/// lines up with [`Seq::push`] (the `map` transition) and [`Seq::update`] (the `unmap` one).
spec fn count(s: Seq<Mapping>, d: nat, g: nat, rw: bool) -> nat
    decreases s.len(),
{
    if s.len() == 0 {
        0
    } else {
        count(s.subrange(0, s.len() - 1), d, g, rw) + b2n(matches(s[s.len() - 1], d, g, rw))
    }
}

// ── the scalar count-transitions, transcribed from hv-core (fidelity anchor #1) ──────────────

/// Saturating subtraction on `nat` — mirrors `u32::saturating_sub` used in the real
/// `counts_after_unmap`.
spec fn sat_sub(a: nat, b: nat) -> nat {
    if a >= b { (a - b) as nat } else { 0 }
}

/// Mirror of `hv_core::grant::System::counts_after_map` (`grant.rs`):
/// ```ignore
/// let maps = maps.checked_add(1)?;                       // (+1; overflow is the Kani proof's job)
/// let writable_maps = if writable { writable_maps + 1 } else { writable_maps };
/// ```
/// The `u32` overflow of `+1` is *not* modeled here (Verus `nat` cannot overflow); it is
/// discharged over all magnitudes by the Kani harness `writable_exceeds_maps_preserved_under_map`.
/// This file's job is the orthogonal `Vec`-length axis.
spec fn counts_after_map(maps: nat, wmaps: nat, w: bool) -> (nat, nat) {
    (maps + 1, wmaps + b2n(w))
}

/// Mirror of `hv_core::grant::System::counts_after_unmap` (`grant.rs`):
/// ```ignore
/// let maps = maps.saturating_sub(1);
/// let writable_maps = if writable { writable_maps.saturating_sub(1) } else { writable_maps };
/// ```
spec fn counts_after_unmap(maps: nat, wmaps: nat, w: bool) -> (nat, nat) {
    (sat_sub(maps, 1), sat_sub(wmaps, b2n(w)))
}

// ── the counting lemmas: how one transition perturbs the cardinality ─────────────────────────

/// **`map` crux.** Appending one mapping to the table increments the matching count by exactly
/// 1 for the appended mapping's own `(d,g,rw)`, and by 0 for every other `(d,g,rw)`. This is
/// the fact a model checker cannot generalize over arbitrary length and Verus proves in one
/// step (`push` semantics + the subrange that drops the appended tail is the original table).
proof fn count_push(s: Seq<Mapping>, nm: Mapping, d: nat, g: nat, rw: bool)
    ensures
        count(s.push(nm), d, g, rw) == count(s, d, g, rw) + b2n(matches(nm, d, g, rw)),
{
    assert(s.push(nm).subrange(0, s.len() as int) =~= s);
}

/// **`unmap` crux.** Overwriting the element at `h` changes the matching count by (new − old)
/// at `h` and nothing else — stated additively to avoid `nat` subtraction. Induction on the
/// table length: if `h` is the last index the tail carries the change; otherwise the last
/// element is untouched and the change is in the recursively-handled prefix.
proof fn count_update(s: Seq<Mapping>, h: int, nm: Mapping, d: nat, g: nat, rw: bool)
    requires
        0 <= h < s.len(),
    ensures
        count(s.update(h, nm), d, g, rw) + b2n(matches(s[h], d, g, rw))
            == count(s, d, g, rw) + b2n(matches(nm, d, g, rw)),
    decreases s.len(),
{
    let s2 = s.update(h, nm);
    let last = (s.len() - 1) as int;
    if h == last {
        assert(s2.subrange(0, last) =~= s.subrange(0, last));
    } else {
        let sub = s.subrange(0, last);
        assert(s2.subrange(0, last) =~= sub.update(h, nm));
        assert(s2[last] == s[last]);
        count_update(sub, h, nm, d, g, rw);
    }
}

/// A matching live member forces the count `≥ 1` — the no-underflow fact that makes
/// `counts_after_unmap`'s saturating subtraction *exact* on the entry actually being unmapped.
proof fn count_positive(s: Seq<Mapping>, i: int, d: nat, g: nat, rw: bool)
    requires
        0 <= i < s.len(),
        matches(s[i], d, g, rw),
    ensures
        count(s, d, g, rw) >= 1,
    decreases s.len(),
{
    let last = (s.len() - 1) as int;
    if i < last {
        count_positive(s.subrange(0, last), i, d, g, rw);
    }
}

// ── single-entry preservation (the scalar↔Vec coupling, for one arbitrary entry) ─────────────

/// `RefcountMismatch` preserved by **`map`** for one arbitrary entry `(d,g)`, over an
/// arbitrary-length table `s`. The map adds a live mapping of grant `(gg,rr)` with writability
/// `w`; the entry's scalars follow `counts_after_map` iff this *is* the mapped entry, else are
/// unchanged — and either way still equal the (post-push) cardinality.
proof fn map_preserves_entry(
    s: Seq<Mapping>,
    d: nat,
    g: nat,
    maps: nat,
    wmaps: nat,
    gg: nat,
    rr: nat,
    w: bool,
)
    requires
        maps == count(s, d, g, false),
        wmaps == count(s, d, g, true),
    ensures
        ({
            let nm = Mapping { active: true, grantor: gg, gref: rr, writable: w };
            let s2 = s.push(nm);
            let (m2, w2) = if d == gg && g == rr {
                counts_after_map(maps, wmaps, w)
            } else {
                (maps, wmaps)
            };
            m2 == count(s2, d, g, false) && w2 == count(s2, d, g, true)
        }),
{
    let nm = Mapping { active: true, grantor: gg, gref: rr, writable: w };
    count_push(s, nm, d, g, false);
    count_push(s, nm, d, g, true);
}

/// `RefcountMismatch` preserved by **`unmap`** for one arbitrary entry `(d,g)`, over an
/// arbitrary-length table `s`. Unmap deactivates the live mapping at handle `h`; the scalars of
/// *its* grant follow `counts_after_unmap`, all others unchanged. `count_positive` supplies the
/// `maps ≥ 1` (and `writable_maps ≥ 1` when the released mapping was writable) that makes the
/// saturating subtraction exact — the very fact the Kani unmap harness had to *assume*.
proof fn unmap_preserves_entry(s: Seq<Mapping>, h: int, d: nat, g: nat, maps: nat, wmaps: nat)
    requires
        maps == count(s, d, g, false),
        wmaps == count(s, d, g, true),
        0 <= h < s.len(),
        s[h].active,
    ensures
        ({
            let dead = Mapping { active: false, ..s[h] };
            let s2 = s.update(h, dead);
            let released = s[h].grantor == d && s[h].gref == g;
            let (m2, w2) = if released {
                counts_after_unmap(maps, wmaps, s[h].writable)
            } else {
                (maps, wmaps)
            };
            m2 == count(s2, d, g, false) && w2 == count(s2, d, g, true)
        }),
{
    let dead = Mapping { active: false, ..s[h] };
    count_update(s, h, dead, d, g, false);
    count_update(s, h, dead, d, g, true);
    if s[h].grantor == d && s[h].gref == g {
        count_positive(s, h, d, g, false);
        if s[h].writable {
            count_positive(s, h, d, g, true);
        }
    }
}

// ── the capstone: the WHOLE-TABLE invariant, ∀ entries × ∀ table size ─────────────────────────

/// The entry table: `(grantor, gref) → (maps, writable_maps)`, one cell per active grant.
/// [`table_ok`] is `first_violation`'s per-entry `RefcountMismatch` check *quantified over
/// every active entry* — the whole invariant, not a single projection.
spec fn table_ok(entries: Map<(nat, nat), (nat, nat)>, s: Seq<Mapping>) -> bool {
    forall|k: (nat, nat)| #[trigger] entries.dom().contains(k) ==>
        entries[k].0 == count(s, k.0, k.1, false) && entries[k].1 == count(s, k.0, k.1, true)
}

/// **`map` preserves the whole table.** Given `RefcountMismatch` on every entry, after a map of
/// live grant `(gg,rr)` — push the mapping, bump only `(gg,rr)`'s scalars by `counts_after_map`
/// — every entry still satisfies `RefcountMismatch`. `(gg,rr)` moves by the crux lemma's `+1`;
/// every other entry is unchanged because the pushed mapping does not match it.
proof fn map_preserves_table(
    entries: Map<(nat, nat), (nat, nat)>,
    s: Seq<Mapping>,
    gg: nat,
    rr: nat,
    w: bool,
)
    requires
        table_ok(entries, s),
        entries.dom().contains((gg, rr)),
    ensures
        ({
            let nm = Mapping { active: true, grantor: gg, gref: rr, writable: w };
            let old = entries[(gg, rr)];
            table_ok(entries.insert((gg, rr), counts_after_map(old.0, old.1, w)), s.push(nm))
        }),
{
    let nm = Mapping { active: true, grantor: gg, gref: rr, writable: w };
    let s2 = s.push(nm);
    let old = entries[(gg, rr)];
    let entries2 = entries.insert((gg, rr), counts_after_map(old.0, old.1, w));
    assert forall|k: (nat, nat)| entries2.dom().contains(k) implies
        (#[trigger] entries2[k]).0 == count(s2, k.0, k.1, false)
            && entries2[k].1 == count(s2, k.0, k.1, true) by {
        count_push(s, nm, k.0, k.1, false);
        count_push(s, nm, k.0, k.1, true);
        if k != (gg, rr) {
            assert(entries.dom().contains(k));
        }
    }
}

/// **`unmap` preserves the whole table.** Deactivating the live mapping at `h` moves only its
/// own grant's scalars (by `counts_after_unmap`); every other entry is unchanged because the
/// deactivated mapping did not match it. The precondition that `(grantor,gref)` is a live entry
/// is `hv-core`'s `DanglingMap` invariant (an active mapping always backs a live grant) — the
/// same reachable-state fact the Kani harness carried as an assumption, here an explicit
/// hypothesis to be discharged by that companion invariant.
proof fn unmap_preserves_table(entries: Map<(nat, nat), (nat, nat)>, s: Seq<Mapping>, h: int)
    requires
        table_ok(entries, s),
        0 <= h < s.len(),
        s[h].active,
        entries.dom().contains((s[h].grantor, s[h].gref)),
    ensures
        ({
            let dead = Mapping { active: false, ..s[h] };
            let key = (s[h].grantor, s[h].gref);
            let old = entries[key];
            table_ok(
                entries.insert(key, counts_after_unmap(old.0, old.1, s[h].writable)),
                s.update(h, dead),
            )
        }),
{
    let dead = Mapping { active: false, ..s[h] };
    let key = (s[h].grantor, s[h].gref);
    let old = entries[key];
    let s2 = s.update(h, dead);
    let entries2 = entries.insert(key, counts_after_unmap(old.0, old.1, s[h].writable));
    count_positive(s, h, s[h].grantor, s[h].gref, false);
    if s[h].writable {
        count_positive(s, h, s[h].grantor, s[h].gref, true);
    }
    assert forall|k: (nat, nat)| entries2.dom().contains(k) implies
        (#[trigger] entries2[k]).0 == count(s2, k.0, k.1, false)
            && entries2[k].1 == count(s2, k.0, k.1, true) by {
        count_update(s, h, dead, k.0, k.1, false);
        count_update(s, h, dead, k.0, k.1, true);
        if k != key {
            assert(entries.dom().contains(k));
        }
    }
}

} // verus!
