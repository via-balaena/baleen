// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # `DeadDomainReferenced`'s device clause, preserved ∀-N — the SMMU arc's rung 4a
//!
//! Rungs 1–3 put the hardware answer in place: a bus master reaches nothing unless this hypervisor
//! bound its StreamID, and a bound one reaches exactly a domain's proven `p2m` frames
//! (`docs/SMMU-TRANSLATION.md`). What none of them contains is a *relation* the stream table
//! refines — device→domain assignment was metal configuration, so nothing said a device belongs to
//! at most one domain, or that a dead domain's device stops reaching memory. This file is the ∀-N
//! half of that relation:
//!
//! > `∀ dev. holder(dev) == Some(d) ⇒ d is Live`
//!
//! preserved by **every transition class that can move the system toward violating it**, over an
//! **arbitrary device population** and an arbitrary domain count.
//!
//! ## Why this invariant and not "at most one holder"
//!
//! The obvious property — a device has at most one holder — is deliberately **absent** here,
//! because it is not an invariant of the code but a property of its *type*: `hv-core`'s
//! `device::System` stores one `Option<DomId>` per device, not a set, so two simultaneous holders
//! cannot be written down. Proving it would be proving something about `Option`, and a proof that
//! could not fail reads as evidence when it is none. What genuinely needs proof is the coupling to
//! the **lifecycle**, because that one *can* break: an assignment is a bare domain id recorded in a
//! system table, it outlives the transition that wrote it, and `hv-core` deliberately has no
//! generation counter — so a reference surviving a teardown would be honoured by whoever is reborn
//! into that slot. A bus master aimed at the next tenant's memory, with no hypercall and no vCPU
//! involved: the confused deputy in the one flavour every CPU-side invariant is blind to.
//!
//! ## The transition audit — which classes can move toward a violation
//!
//! The invariant reads two things: the **assignment** relation and the **liveness** vector. So it
//! can break in exactly two ways — an assignment appears naming a non-live domain, or a domain
//! that is already named stops being live. Enumerating every transition against those two
//! (design-lesson #3) gives:
//!
//! | transition | why it preserves | shape |
//! |---|---|---|
//! | `device_assign` | the mint gate refuses a non-`Live` assignee | guard |
//! | `device_release` | strictly fewer assignments | monotone |
//! | `DomainCreate` | strictly more live domains | monotone |
//! | `DomainDestroy` | the **only** transition that removes liveness — and it sweeps exactly that domain's assignments in the same step | guard + sweep |
//! | grant, evtchn, sched, p2m, control | touch neither the assignment relation nor liveness | no-op |
//!
//! Two things that audit makes plain, and neither is obvious from reading the code:
//!
//! * **`DomainDestroy` is the whole difficulty.** Every other class moves one side of the coupling
//!   in the safe direction. Destroy is the only one that moves liveness *down*, so it is the only
//!   one whose preservation needs an argument rather than monotonicity — and the argument is
//!   precisely the sweep. Remove it and the invariant is false at once (in the code, and in
//!   [`destroy_preserves`] below, which Verus then rejects).
//! * **The mint gate is currently masked, and that is recorded rather than relied on.** In the
//!   shipped seam a caller must *control* the assignee, and a control edge already requires a live
//!   target (`ControlEdgeDeadEndpoint`), so `reject_dead_target` cannot fire today. The guard is
//!   kept, and appears here as a hypothesis, because "an assignment names a live domain" is a
//!   property of assignment — not a consequence of how authority happens to be gated. A lemma
//!   whose hypothesis is another subsystem's invariant staying arranged as it is has no teeth of
//!   its own.
//!
//! ## The division of labour with Kani
//!
//! `hv-verify::device_assignment` proves the same transitions **total and exactly-scoped over every
//! assignment vector** on the *shipped* `hv_core::device` code — but at a bounded device count (2),
//! because the collection axis is what Kani must unwind. This file is the ∀-**size** half: every
//! statement below quantifies over a `Seq` of arbitrary length. Neither subsumes the other, and the
//! headline "∀-N" is exactly their conjunction plus the enumerator's real-code sweep.
//!
//! ## Fidelity (a mirror, managed)
//!
//! [`inv`] mirrors the device clause of `hypervisor.rs::is_unreferenced`, which
//! `first_cross_violation` reports as `CrossViolation::DeadDomainReferenced`.
//! [`sweeps_holder`] is the postcondition of `device::System::release_all_of`, transcribed from its
//! body (clear every slot equal to the holder, touch no other). The `assign`/`release` lemmas'
//! hypotheses are the real guards from `Hypervisor::device_assign` / `device_release`.
//!
//! ## Non-vacuity (validated by hand; recorded in `hv-verify/verus/README.md`)
//!
//! Dropping `live(to)` from [`assign_preserves`], or the [`sweeps_holder`] hypothesis from
//! [`destroy_preserves`], each makes Verus **reject** the proof. [`sweep_is_exact`] is the twin
//! that fails in the other direction: a sweep that cleared *every* device would satisfy "nothing
//! names the destroyed domain" while silently disarming every other domain's devices, which no
//! state predicate would ever flag — so the "others unchanged" conclusion is proven beside it.
//!
//! Run: `verus --crate-type=lib hv-verify/verus/device_assignment_preservation.rs` (exit 0 = all
//! proven).

use vstd::prelude::*;

verus! {

/// A domain id. `int` is the honest ∀-size domain (the data-independence reduction — no transition
/// or invariant branches on a literal id).
type Id = int;

/// Which domains are currently `Live` — mirror of `Hypervisor::life`.
type Live = spec_fn(Id) -> bool;

/// The assignment relation: one entry per device, `Some(d)` iff `d` holds it. A `Seq<Option<Id>>`
/// rather than a set-valued map, mirroring `device::System`'s `Vec<Option<DomId>>` — which is what
/// makes exclusivity a fact about the representation rather than a proof obligation.
type Assign = Seq<Option<Id>>;

/// **The invariant.** The device clause of `DeadDomainReferenced`: nothing in the assignment
/// relation names a domain that is not live.
spec fn inv(a: Assign, live: Live) -> bool {
    forall|d: int| #![trigger a[d]]
        0 <= d < a.len() ==> match a[d] {
            Some(h) => live(h),
            None => true,
        }
}

// ─── device_assign — the guard case ───────────────────────────────────────────────────

/// **`device_assign` preserves it.** The only new entry names `to`, and the mint gate has already
/// established that `to` is live.
///
/// The transition is stated **totally** — either the call was refused and the relation is
/// untouched, or it wrote one in-range slot — rather than assuming a valid index. That is the
/// shape of the real function (it returns `BadDevice`/`BadDomain`/`Busy` without writing), and
/// assuming the index valid would quietly move a totality obligation onto the callers, where
/// nothing checks it.
proof fn assign_preserves(a: Assign, a2: Assign, live: Live, dev: int, to: Id)
    requires
        inv(a, live),
        // The mint gate: `Hypervisor::device_assign`'s `reject_dead_target(to)`.
        live(to),
        // `device::System::assign`: refuse and write nothing, or set exactly one slot.
        a2 == a || (0 <= dev < a.len() && a2 == a.update(dev, Some(to))),
    ensures
        inv(a2, live),
{
    if a2 != a {
        assert forall|d: int| #![trigger a2[d]] 0 <= d < a2.len() implies match a2[d] {
            Some(h) => live(h),
            None => true,
        } by {
            if d == dev {
                // The written slot names `to`, which the gate proved live.
            } else {
                assert(a2[d] == a[d]);
            }
        }
    }
}

// ─── device_release — the monotone case ───────────────────────────────────────────────

/// **`device_release` preserves it.** Strictly fewer assignments: the only slot that changes
/// becomes `None`, which imposes nothing.
proof fn release_preserves(a: Assign, a2: Assign, live: Live, dev: int)
    requires
        inv(a, live),
        a2 == a || (0 <= dev < a.len() && a2 == a.update(dev, None::<Id>)),
    ensures
        inv(a2, live),
{
    if a2 != a {
        assert forall|d: int| #![trigger a2[d]] 0 <= d < a2.len() implies match a2[d] {
            Some(h) => live(h),
            None => true,
        } by {
            if d != dev {
                assert(a2[d] == a[d]);
            }
        }
    }
}

// ─── DomainCreate — the other monotone case ───────────────────────────────────────────

/// **`DomainCreate` preserves it.** Liveness only grows, and the invariant is monotone in it: a
/// holder that was live stays live. (Creation touches the assignment relation not at all — a
/// created domain begins holding nothing, which the seam asserts via `is_unreferenced` and this
/// lemma does not need.)
proof fn create_preserves(a: Assign, live: Live, live2: Live, target: Id)
    requires
        inv(a, live),
        forall|x: Id| #![trigger live2(x)] live2(x) == (live(x) || x == target),
    ensures
        inv(a, live2),
{
    assert forall|d: int| #![trigger a[d]] 0 <= d < a.len() implies match a[d] {
        Some(h) => live2(h),
        None => true,
    } by {
        if let Some(h) = a[d] {
            assert(live(h));
            assert(live2(h));
        }
    }
}

// ─── DomainDestroy — the only class that needs the sweep ──────────────────────────────

/// The postcondition of `device::System::release_all_of(holder)`, transcribed from its body: every
/// slot naming `holder` is cleared, and **every other slot is untouched**.
///
/// Both halves are stated because they fail in opposite directions, and only one of them would be
/// caught by any invariant. Too little and a bus master outlives its holder into a reborn slot;
/// too much and destroying one domain silently disarms every *other* domain's devices — a denial of
/// service that leaves the invariant perfectly satisfied.
spec fn sweeps_holder(a: Assign, a2: Assign, holder: Id) -> bool {
    &&& a2.len() == a.len()
    &&& forall|d: int| #![trigger a[d]]
        0 <= d < a.len() ==> a2[d] == if a[d] == Some(holder) {
            None::<Id>
        } else {
            a[d]
        }
}

/// **`DomainDestroy` preserves it** — the one transition that removes liveness, and therefore the
/// only one whose preservation is not monotonicity.
///
/// The sweep and the liveness change happen in the same step, which is what makes this provable at
/// all: the invariant is *momentarily* false between them and no reachable state ever observes
/// that, because `hv-core`'s teardown is a single transition.
proof fn destroy_preserves(a: Assign, a2: Assign, live: Live, live2: Live, target: Id)
    requires
        inv(a, live),
        // Teardown's device sweep — `device::System::release_all_of(target)`.
        sweeps_holder(a, a2, target),
        // Teardown's lifecycle write — `life[target] = Dead`, everyone else unchanged.
        forall|x: Id| #![trigger live2(x)] live2(x) == (live(x) && x != target),
    ensures
        inv(a2, live2),
{
    assert forall|d: int| #![trigger a2[d]] 0 <= d < a2.len() implies match a2[d] {
        Some(h) => live2(h),
        None => true,
    } by {
        assert(a2[d] == if a[d] == Some(target) { None::<Id> } else { a[d] });
        if let Some(h) = a2[d] {
            // Not swept ⇒ the slot is unchanged and does not name `target`, so its holder was
            // live before and is still live now.
            assert(a[d] == Some(h));
            assert(h != target);
            assert(live(h));
        }
    }
}

/// **The sweep is exact.** After teardown, no device names the destroyed domain — and every device
/// held by anyone else holds exactly what it held.
///
/// The first conclusion is what the invariant needs; the second is what nothing else would ever
/// check. Stated together so a sweep that over-reaches is as visible as one that under-reaches.
proof fn sweep_is_exact(a: Assign, a2: Assign, target: Id)
    requires
        sweeps_holder(a, a2, target),
    ensures
        forall|d: int| #![trigger a2[d]] 0 <= d < a2.len() ==> a2[d] != Some(target),
        forall|d: int| #![trigger a[d]]
            0 <= d < a.len() && a[d] != Some(target) ==> a2[d] == a[d],
{
    assert forall|d: int| #![trigger a2[d]] 0 <= d < a2.len() implies a2[d] != Some(target) by {
        assert(a2[d] == if a[d] == Some(target) { None::<Id> } else { a[d] });
    }
}

// ─── the base case ────────────────────────────────────────────────────────────────────

/// **Initiation.** `device::System::new` starts every device unassigned, so the invariant holds
/// vacuously at boot whatever the liveness vector is. With the preservation lemmas above this
/// gives induction over reachable states — and it is worth stating rather than waving at, because
/// it is also the *fail-closed default* the metal refines: an unassigned device is refined to a
/// **denying** stream-table entry, so the model's default and the hardware's are the same default
/// rather than two that happen to agree.
proof fn boot_state_satisfies_it(a: Assign, live: Live)
    requires
        forall|d: int| #![trigger a[d]] 0 <= d < a.len() ==> a[d] === None::<Id>,
    ensures
        inv(a, live),
{
}

} // verus!

fn main() {}
