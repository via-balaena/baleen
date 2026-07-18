// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Tier C / Verus — the projection frame-lemma (owner-locality of the grant summation)
//!
//! The second §3 residual (`docs/TIER-B-CUTOFF.md` §2.3, §3(2)). Tier B's size cutoff (a
//! violation at *any* size N projects to one at size ≤ k0) rests on a **frame property**: a
//! transition on entities disjoint from a violation's witness W does not perturb W's
//! invariant-observable state. Tier B stated it, justified it per transition class, and marked
//! it as the load-bearing deductive obligation it could not discharge by enumeration — because
//! it quantifies over *all* states. This file discharges its substantive case.
//!
//! ## Which case, and why it is the load-bearing one
//!
//! Of §2.3's three frame-property bullets — slot-reuse index-independence, the grant summation's
//! owner-locality, and the single-referrer scans — the summation is the only one that crosses
//! domains, so it is the only one where "a disjoint transition can't perturb the witness" is
//! non-trivial. The invariant is `UnbackedGrantMap` (`hv-core/src/hypervisor.rs`,
//! `first_cross_violation`):
//!
//! > for each grant with live maps over frame `f`, `refs(f) ≥ maps_over_frame(f)` (and the
//! > writable analogue), where **`maps_over_frame(f)`** (`hypervisor.rs`) sums `map_count`
//! > across **every** grantor's grants that name `f`.
//!
//! That sum ranges over *all* domains — so at face value a transition on any domain could
//! change it. It cannot, and the reason is a **cross-invariant coupling**: `UnbackedGrantMap`
//! is checked only *after* `MisownedGrantMap`, which fires unless every grant with live maps
//! over `f` is granted by `owner(f)`. So in any state where the invariants hold, a grant of `f`
//! by a domain `D ≠ owner(f)` carries **no** live maps and contributes **0** to the sum. The
//! summation is therefore **owner-local**: its value is a function only of `{f, owner(f)}` —
//! exactly the witness W of `UnbackedGrantMap` (§2.2: 1 frame + its owner) — so any transition
//! disjoint from W leaves it unchanged. This mirrors, at the frame-lemma level, the same
//! *"one scalar invariant borrows from a relational one"* shape the Kani spike found for
//! `WritableExceedsMaps` (design-lesson #20): `UnbackedGrantMap`'s locality borrows from
//! `MisownedGrantMap`.
//!
//! ## What is proven
//!
//! Modeling each grant projected to what `maps_over_frame` reads — `(grantor, frame, count)`,
//! where `count` is `map_count` (or `writable_map_count`; one generic `count` serves both
//! totals) — over an **arbitrary-length** grant population `Seq<Grant>`:
//!
//! * `owner_local` — under the misowned hypothesis, `sum_frame(gs,f) == sum_frame_by(gs,f,o)`:
//!   the whole-population sum equals the owner-only sum (non-owner grants contribute 0).
//! * `frame_property` — the total is a function *only* of `owner(f)`'s grants of `f`: two
//!   populations agreeing on that owner-projection have equal totals. This is the frame
//!   property in the form §2.3's projection construction imports (dropping a disjoint
//!   transition, which leaves the owner-projection fixed, preserves the read-value at `f`).
//! * `disjoint_append_preserves` — a concrete disjoint step (a domain `≠ owner(f)` granting a
//!   frame; a fresh grant has no live maps, and the misowned hypothesis forbids a live
//!   non-owner grant of `f`) preserves the total, the owner-projection, **and** the hypothesis.
//!
//! ## Fidelity (a mirror, managed — same discipline as `refcount_mismatch.rs`)
//!
//! `sum_frame` mirrors `maps_over_frame`'s double loop (sum of `map_count` over grants naming
//! `f`; the real one `saturating_add`s — the `u32` saturation is the Kani-territory magnitude
//! concern, a no-op here on `nat`). `misowned_ok` mirrors "`MisownedGrantMap` does not fire at
//! `f`": a live map (`count > 0`) over `f` forces `grantor == owner(f)`. The enumerator already
//! checks `UnbackedGrantMap`/`MisownedGrantMap` together on the *real* `Hypervisor` at small
//! size (Tier A `grant_p2m_3dom_cfg`); this adds the ∀-size frame property. See
//! `hv-verify/verus/README.md`.
//!
//! ## Non-vacuity (validated)
//!
//! Dropping the misowned hypothesis from `owner_local`, or the "no live misowned map" guard from
//! `disjoint_append_preserves`, makes Verus reject the proof — the coupling is load-bearing, not
//! decorative (verified by hand; recorded in `hv-verify/verus/README.md`).
//!
//! Run: `verus --crate-type=lib hv-verify/verus/frame_lemma.rs` (exit 0 = all proven).

use vstd::prelude::*;

verus! {

/// One grant, projected to what `maps_over_frame` reads: its grantor, the frame it names, and
/// the summed count — `map_count` for the `maps` total, `writable_map_count` for the writable
/// total (one generic `count` serves both). ids are `nat` (the §2.1 reduction: only sizes
/// matter, so unbounded `nat` is the honest ∀-size domain).
struct Grant {
    grantor: nat,
    frame: nat,
    count: nat,
}

/// `Σ count over grants naming f` — mirror of `hypervisor.rs::maps_over_frame`'s double loop,
/// which adds `map_count(grantor,gref)` for every `(grantor,gref)` whose `granted_frame == f`.
spec fn sum_frame(gs: Seq<Grant>, f: nat) -> nat
    decreases gs.len(),
{
    if gs.len() == 0 {
        0
    } else {
        let last = gs[gs.len() - 1];
        sum_frame(gs.subrange(0, gs.len() - 1), f) + (if last.frame == f { last.count } else { 0nat })
    }
}

/// The same sum restricted to grants granted by `o` — the owner-projection of the summation.
spec fn sum_frame_by(gs: Seq<Grant>, f: nat, o: nat) -> nat
    decreases gs.len(),
{
    if gs.len() == 0 {
        0
    } else {
        let last = gs[gs.len() - 1];
        sum_frame_by(gs.subrange(0, gs.len() - 1), f, o) + (if last.frame == f && last.grantor == o {
            last.count
        } else {
            0nat
        })
    }
}

/// The `MisownedGrantMap` hypothesis for frame `f` owned by `o`: no grant naming `f` with a
/// **live** count (`> 0`) is granted by anyone but the owner. Exactly "`MisownedGrantMap` does
/// not fire at `f`" — a live map over `f` forces `grantor == owner(f)` (`first_cross_violation`).
spec fn misowned_ok(gs: Seq<Grant>, f: nat, o: nat) -> bool {
    forall|i: int| #![trigger gs[i]]
        0 <= i < gs.len() ==> (gs[i].frame == f && gs[i].count > 0 ==> gs[i].grantor == o)
}

/// **The deductive heart.** Under the misowned hypothesis the whole-population summation equals
/// the owner-only summation — every non-owner grant of `f` contributes 0. Induction peeling the
/// last grant: a last grant naming `f` and granted by a non-owner must, by the hypothesis, have
/// `count == 0`, so it adds 0 to *both* sums; every other case the two sums move together.
proof fn owner_local(gs: Seq<Grant>, f: nat, o: nat)
    requires
        misowned_ok(gs, f, o),
    ensures
        sum_frame(gs, f) == sum_frame_by(gs, f, o),
    decreases gs.len(),
{
    if gs.len() > 0 {
        let prefix = gs.subrange(0, gs.len() - 1);
        assert(misowned_ok(prefix, f, o)) by {
            assert forall|i: int| #![trigger prefix[i]]
                0 <= i < prefix.len() && prefix[i].frame == f && prefix[i].count > 0 implies
                    prefix[i].grantor == o by {
                assert(prefix[i] == gs[i]);
            }
        }
        owner_local(prefix, f, o);
    }
}

/// **The frame property (congruence).** The `UnbackedGrantMap` read-value at `f` is a function
/// *only* of `owner(f)`'s grants of `f`: two populations that agree on the owner-projection (and
/// both satisfy the misowned hypothesis) have the same total. This is the form §2.3's projection
/// construction imports — a transition that leaves `owner(f)`'s grants of `f` fixed leaves the
/// value at `f` unchanged, so dropping the disjoint transitions from a violating trace preserves
/// the violation at the witness `{f, owner(f)}`.
proof fn frame_property(gs: Seq<Grant>, gs2: Seq<Grant>, f: nat, o: nat)
    requires
        misowned_ok(gs, f, o),
        misowned_ok(gs2, f, o),
        sum_frame_by(gs, f, o) == sum_frame_by(gs2, f, o),
    ensures
        sum_frame(gs, f) == sum_frame(gs2, f),
{
    owner_local(gs, f, o);
    owner_local(gs2, f, o);
}

/// **A concrete disjoint step.** A domain other than `owner(f)` grants a frame — a fresh grant
/// has no live maps (`count == 0`), and the misowned hypothesis forbids a *live* non-owner grant
/// of `f`, so such a step names a different frame or carries no live map. It preserves the total,
/// the owner-projection, **and** the hypothesis: dropping it from a trace changes nothing
/// observable at `f`. This is a witness that the frame property models a *real* disjoint
/// transition (a non-owner `grant_access`), not just an abstract congruence.
proof fn disjoint_append_preserves(gs: Seq<Grant>, g: Grant, f: nat, o: nat)
    requires
        misowned_ok(gs, f, o),
        g.grantor != o,
        g.frame != f || g.count == 0,
    ensures
        sum_frame(gs.push(g), f) == sum_frame(gs, f),
        sum_frame_by(gs.push(g), f, o) == sum_frame_by(gs, f, o),
        misowned_ok(gs.push(g), f, o),
{
    let gs2 = gs.push(g);
    assert(gs2.subrange(0, gs.len() as int) =~= gs);
    assert(misowned_ok(gs2, f, o)) by {
        assert forall|i: int| #![trigger gs2[i]]
            0 <= i < gs2.len() && gs2[i].frame == f && gs2[i].count > 0 implies gs2[i].grantor
            == o by {
            if i < gs.len() {
                assert(gs2[i] == gs[i]);
            } else {
                assert(gs2[i] == g);
            }
        }
    }
}

} // verus!
