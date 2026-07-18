// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Tier D / Verus — the control-channel unwinding lemma (authority / affinity local respect)
//!
//! The **third** per-channel local-respect lemma of Tier D (`frame_lemma.rs` = the memory
//! channel, `unwinding_signal.rs` = the signal channel; this = the **authority/control**
//! channel), and a third cost datapoint before the one genuinely multi-domain obligation (the
//! `DomainDestroy` cascade) is attempted. See `docs/TIER-D-NONINTERFERENCE.md`.
//!
//! ## Which transition, and the finding that makes this channel *different*
//!
//! `obs(a)` (`hv-sim/src/noninterference.rs`) includes `a`'s vCPUs — run-state and **affinity
//! mask**. The scheduler transitions split two ways:
//!
//! * **caller-only** ops (`SchedAdmit/Run/Preempt/Block/Wake/Offline`) act on the *caller's
//!   own* vCPUs — their write-set is domain `caller`'s vCPU entries;
//! * **`SchedSetAffinity{target, vcpu, mask}`** is the one scheduler op with a *`target`*
//!   parameter — a whole-domain **control** operation (design-lesson #16), so it is gated by
//!   the **authority** relation: `caller == target` (a domain affining its own vCPUs) **or**
//!   `controls[caller][target]` (`hypervisor.rs`, the same per-target gate `DomainDestroy`
//!   uses, [`HvError::Denied`] otherwise).
//!
//! The non-interference **channel relation** (`noninterference.rs`) authorizes `b ⇝ a` via
//! this channel iff `controls[b][a]`. So local respect for the vCPU projection needs: a
//! scheduler step by `b` with no authority over `a` (and `b ≠ a`) leaves `a`'s vCPUs unchanged.
//!
//! **The finding.** Unlike the memory channel (locality *borrows from* `MisownedGrantMap`) and
//! the signal channel (locality *borrows from* reciprocity), the authority channel's locality
//! comes **directly from a transition guard** — the `SchedSetAffinity` authority check *is* the
//! write-restriction. This is design-lesson #9 (authorization is a *transition guard*, not a
//! *state invariant*) seen from the non-interference side: for a guard-channel there is no
//! relational state invariant to bridge two sides, because the transition *itself* names the
//! only domain it may write. That makes this the *simplest* of the three channels — a datapoint
//! that per-channel local respect is not uniformly hard.
//!
//! ## What is proven
//!
//! Model the affinity table as `aff: (dom, vcpu) ↦ mask` and control as a set of present edges.
//!
//! * `set_affinity_target_not_a` — **the deductive heart.** If `b` does not control `a` and
//!   `b ≠ a`, then the `SchedSetAffinity` guard (`authorized(b, target)`) forces `target ≠ a`.
//!   (Contrapositive: an authorized write with `target == a` needs `b == a` or the `(b,a)`
//!   control edge — both excluded.) This is the guard-is-the-write-restriction step.
//! * `set_affinity_preserves_a` — a concrete `SchedSetAffinity` by `b`: under the same
//!   hypotheses, the affinity write touches no `(a, ·)` entry, so `obs(a)`'s vCPU-affinity
//!   projection is preserved.
//! * `caller_only_sched_preserves_a` — the caller-only scheduler ops: a write confined to
//!   domain `b`'s vCPU entries with `b ≠ a` preserves every `(a, ·)` entry — the (even simpler)
//!   locality that covers the run-state half of the vCPU projection, needing only `b ≠ a`.
//!
//! ## Fidelity (a mirror, managed — same discipline as the other Tier-D/­C proofs)
//!
//! `authorized` mirrors the `SchedSetAffinity` guard in `hypervisor.rs::sched_set_affinity`
//! (`caller == target || controls(caller, target)`); the affinity write mirrors
//! `sched::set_affinity` storing the mask on `(target, vcpu)`. The **enumerator bridge**
//! (`hv-sim/src/noninterference.rs`) already checks this local-respect condition on the *real*
//! `Hypervisor` over every reachable small state (`dropping_control_channel_is_caught` pins the
//! term load-bearing); Verus adds the ∀-N (arbitrary vCPU population) step.
//!
//! ## Non-vacuity (validated)
//!
//! Dropping the `!controls.contains((b, a))` hypothesis from `set_affinity_target_not_a` makes
//! Verus reject it — a controller *can* move `a`'s affinity, so the control edge is exactly the
//! authorization. (Recorded in `hv-verify/verus/README.md`.)
//!
//! Run: `verus --crate-type=lib hv-verify/verus/unwinding_control.rs` (exit 0 = all proven).

use vstd::prelude::*;

verus! {

/// A vCPU coordinate `(domain, vcpu index)`. ids are `int` (the §2.1 reduction: only sizes
/// matter, so the unbounded integer domain is the honest ∀-size model).
type Vcpu = (int, int);

/// The set of present control edges: `controls.contains((h, t))` iff holder `h` controls
/// target `t` (`Control != Absent` in `hypervisor.rs`). Mirror of the `controls` matrix's
/// presence query used by the `SchedSetAffinity` authority gate.
type Controls = Set<(int, int)>;

/// The `SchedSetAffinity` **authority guard** (`hypervisor.rs::sched_set_affinity`): a domain
/// may set its *own* vCPUs' affinity (`caller == target`), or a peer's if it *controls* that
/// peer (`controls[caller][target]`). The same per-target gate `DomainDestroy` uses — the
/// authority axis (design-lesson #9/#16). This *is* the write-restriction the lemma exploits.
spec fn authorized(controls: Controls, caller: int, target: int) -> bool {
    caller == target || controls.contains((caller, target))
}

/// **The deductive heart.** If `b` does not control `a` and `b ≠ a`, the `SchedSetAffinity`
/// guard forces any target `b` may write to be *not* `a`: an authorized write to `a` would need
/// `b == a` or the `(b, a)` control edge, both excluded. The channel-locality comes straight
/// from the guard — no relational state invariant needed (contrast the grant/evtchn channels).
proof fn set_affinity_target_not_a(controls: Controls, b: int, a: int, target: int)
    requires
        b != a,
        !controls.contains((b, a)),
        authorized(controls, b, target),
    ensures
        target != a,
{
    // authorized(b, target) == (b == target || controls.contains((b, target))). If target were
    // a, the first disjunct is `b == a` (false) and the second is `controls.contains((b, a))`
    // (false), contradicting the guard — so target != a.
}

/// **A concrete `SchedSetAffinity` preserves `obs(a)`.** Writing `mask` to `(target, v0)` under
/// the guard, with `b` lacking authority over `a` and `b ≠ a`, leaves every `(a, ·)` affinity
/// entry — membership and value — unchanged: `obs(a)`'s vCPU-affinity projection is preserved.
proof fn set_affinity_preserves_a(
    controls: Controls,
    aff: Map<Vcpu, int>,
    b: int,
    a: int,
    target: int,
    v0: int,
    mask: int,
)
    requires
        b != a,
        !controls.contains((b, a)),
        authorized(controls, b, target),
    ensures
        forall|v: int| #![trigger aff.insert((target, v0), mask)[(a, v)]]
            {
                let aff2 = aff.insert((target, v0), mask);
                &&& aff2.dom().contains((a, v)) == aff.dom().contains((a, v))
                &&& aff.dom().contains((a, v)) ==> aff2[(a, v)] == aff[(a, v)]
            },
{
    set_affinity_target_not_a(controls, b, a, target);
    // target != a, so (a, v) != (target, v0) for every v — `insert` neither adds nor changes
    // any (a, ·) key. Verus discharges `Map::insert`'s dom/index semantics per key.
    assert forall|v: int| #![trigger aff.insert((target, v0), mask)[(a, v)]]
        {
            let aff2 = aff.insert((target, v0), mask);
            &&& aff2.dom().contains((a, v)) == aff.dom().contains((a, v))
            &&& aff.dom().contains((a, v)) ==> aff2[(a, v)] == aff[(a, v)]
        } by {
        assert((a, v) != (target, v0));
    }
}

/// **A caller-only scheduler op preserves `obs(a)`.** The run-state ops
/// (`Admit/Run/Preempt/Block/Wake/Offline`) act on the *caller's own* vCPUs — a write confined
/// to `(b, ·)` entries. With `b ≠ a` that touches no `(a, ·)` entry, so `a`'s vCPU run-state
/// projection is preserved with no authority hypothesis at all — the simplest locality, and the
/// reason the run-state half of the projection needs no channel. Stated as: any post-state that
/// agrees with `aff` off the `(b, ·)` rows agrees with it on the `(a, ·)` rows.
proof fn caller_only_sched_preserves_a(aff: Map<Vcpu, int>, aff2: Map<Vcpu, int>, b: int, a: int)
    requires
        b != a,
        // The write is confined to `b`'s rows: off `b`'s rows, `aff2` equals `aff`.
        forall|k: Vcpu| #![trigger aff2.dom().contains(k)]
            k.0 != b ==> (aff2.dom().contains(k) == aff.dom().contains(k) && (aff.dom().contains(
                k,
            ) ==> aff2[k] == aff[k])),
    ensures
        forall|v: int| #![trigger aff2.dom().contains((a, v))]
            aff2.dom().contains((a, v)) == aff.dom().contains((a, v)) && (aff.dom().contains(
                (a, v),
            ) ==> aff2[(a, v)] == aff[(a, v)]),
{
    // Every `(a, ·)` key has first component `a != b`, so it falls in the "off b's rows" case.
    assert forall|v: int| #![trigger aff2.dom().contains((a, v))]
        aff2.dom().contains((a, v)) == aff.dom().contains((a, v)) && (aff.dom().contains((a, v))
            ==> aff2[(a, v)] == aff[(a, v)]) by {
        assert((a, v).0 != b);
    }
}

} // verus!
