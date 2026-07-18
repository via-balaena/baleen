// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Tier D / Verus — the creation-channel unwinding lemma (`DomainCreate` local respect)
//!
//! The **fourth** and last *direct*-channel local-respect lemma of Tier D (memory =
//! `frame_lemma.rs`, signal = `unwinding_signal.rs`, authority = `unwinding_control.rs`; this =
//! the **creation** channel). With it, every direct channel of the authorized-channel relation
//! is discharged ∀-N, leaving only the one genuinely multi-domain obligation — the
//! `DomainDestroy` cascade — and the compositional assembly. See
//! `docs/TIER-D-NONINTERFERENCE.md`.
//!
//! ## Which transition, and why the resource projection is trivial
//!
//! `obs(a)` (`hv-sim/src/noninterference.rs`) includes `a`'s liveness `life[a]`. The transition
//! that flips it up is `DomainCreate{target, may_create}` (`hypervisor.rs::domain_create`): it
//! lifts a `Dead` slot to `Live`. Two guards: the **creation capability**
//! (`may_create[caller]`, else [`HvError::Denied`]) and the **lifecycle** precondition (`target`
//! must be `Dead`, else [`HvError::AlreadyAlive`]).
//!
//! Crucially, creation **adds no resources**: a `Dead` slot is a *provably-clean shell*
//! (`DeadDomainNotClean` — owns no frame, offers/holds no grant, has no bound port or online
//! vCPU), so a freshly created domain starts empty. `DomainCreate` writes only `life[target]`,
//! `may_create[target]`, and the creator's `Root` control edge — of which only `life[target]`
//! is in `obs(a)` (authority is excluded from `obs`, §2.1 of the design doc; and the resource
//! tables are untouched by construction). So the whole content of creation-channel local respect
//! is **`life[a]`**.
//!
//! ## The finding — creation is the *second* guard-channel
//!
//! The non-interference **channel relation** authorizes `b ⇝ a` via creation iff
//! `may_create[b] ∧ ¬live[a]` (`b` may bring the `Dead` slot `a` to life). Like the authority
//! channel (`unwinding_control.rs`), the creation channel's locality comes **straight from the
//! transition guards**, not from a relational state invariant: the `DomainCreate` guards
//! (`may_create[b] ∧ ¬live[target]`) *are* the write-restriction on `life[a]`. So the four
//! direct channels split two-and-two: **memory / signal borrow from a state invariant**
//! (`MisownedGrantMap` / reciprocity — a two-sides bridge), **authority / creation come from a
//! transition guard** (design-lesson #9 — the guard names the only slot it may write, so no
//! bridge is needed). Guard-channels are the simpler kind.
//!
//! ## What is proven
//!
//! Model `live` and `may_create` as `dom ↦ bool` maps and `DomainCreate(b, t)` as the guarded
//! lift of `life[t]`.
//!
//! * `create_target_not_a` — **the deductive heart.** If `b` has no creation channel to `a`
//!   (`¬(may_create[b] ∧ ¬live[a])`) and the create guard fired (`may_create[b] ∧ ¬live[t]`),
//!   then `t ≠ a`: the guard's `may_create[b]` forces the channel's other disjunct `live[a]`,
//!   which contradicts the guard's `¬live[t]` if `t = a`.
//! * `create_preserves_life_a` — the concrete transition: `DomainCreate(b, t)` (which lifts
//!   `life[t]` when its guard holds, and is a no-op otherwise) leaves `life[a]` unchanged
//!   whenever `b` has no creation channel to `a`. So `obs(a)` (whose creation-touchable
//!   component is exactly `life[a]`) is preserved.
//!
//! ## Fidelity (a mirror, managed — same discipline as the other Tier-D/­C proofs)
//!
//! `create_guard` mirrors `domain_create`'s two preconditions (`may_create[caller]` and `target`
//! `Dead`); `life_after_create` mirrors its sole `obs`-visible write (`life[target] := Live`).
//! The **enumerator bridge** (`hv-sim/src/noninterference.rs`) already checks this local-respect
//! condition on the *real* `Hypervisor` over every reachable small state (the `create` term is
//! exercised there — the three-domain sweep builds `may_create`-minted creators); Verus adds the
//! ∀-N (arbitrary domain count) step.
//!
//! ## Non-vacuity (validated)
//!
//! Dropping the `!creation_channel(..)` hypothesis from `create_target_not_a` makes Verus reject
//! it — a `may_create` domain *can* bring `a` to life, so that capability is exactly the
//! authorization. (Recorded in `hv-verify/verus/README.md`.)
//!
//! Run: `verus --crate-type=lib hv-verify/verus/unwinding_create.rs` (exit 0 = all proven).

use vstd::prelude::*;

verus! {

/// A domain id (`int` — the §2.1 reduction: only sizes matter, so the unbounded integer domain
/// is the honest ∀-size model, here ∀ domain count).
type Dom = int;

/// The `DomainCreate` guard (`hypervisor.rs::domain_create`): the caller must hold the creation
/// capability (`may_create[caller]`) and the target must currently be `Dead` (`¬live[target]`).
/// This *is* the write-restriction on `life` the lemma exploits.
spec fn create_guard(may_create: Map<Dom, bool>, live: Map<Dom, bool>, caller: Dom, t: Dom) -> bool {
    may_create[caller] && !live[t]
}

/// The non-interference **creation channel**: `b ⇝ a` iff `b` may create and `a` is `Dead`
/// (`noninterference.rs` — `may_create[b] ∧ ¬live[a]`). The one channel gated by the *global*
/// creation capability rather than a per-target relation.
spec fn creation_channel(may_create: Map<Dom, bool>, live: Map<Dom, bool>, b: Dom, a: Dom) -> bool {
    may_create[b] && !live[a]
}

/// `life` after `DomainCreate(b, t)`: lifts `t` to `Live` when the guard holds; a no-op
/// otherwise (a denied / already-alive create mutates nothing). This is the only `obs`-visible
/// effect of creation (it adds no resources — the `Dead` slot was a clean shell).
spec fn life_after_create(live: Map<Dom, bool>, may_create: Map<Dom, bool>, b: Dom, t: Dom) -> Map<
    Dom,
    bool,
> {
    if create_guard(may_create, live, b, t) {
        live.insert(t, true)
    } else {
        live
    }
}

/// **The deductive heart.** If `b` has no creation channel to `a` and the create guard fired,
/// the target is not `a`: the guard's `may_create[b]` forces the channel's other disjunct
/// (`live[a]`), which contradicts the guard's `¬live[t]` when `t = a`. The channel-locality
/// comes straight from the guards — no relational state invariant (contrast memory/signal).
proof fn create_target_not_a(may_create: Map<Dom, bool>, live: Map<Dom, bool>, b: Dom, a: Dom, t: Dom)
    requires
        !creation_channel(may_create, live, b, a),
        create_guard(may_create, live, b, t),
    ensures
        t != a,
{
    // guard ⟹ may_create[b]; ¬channel ⟹ ¬may_create[b] ∨ live[a]; so live[a]. guard ⟹ ¬live[t].
    // If t == a then ¬live[a], contradicting live[a] — so t != a.
}

/// **A concrete `DomainCreate` preserves `obs(a)`.** `DomainCreate(b, t)` — which lifts `life[t]`
/// when its guard holds and is a no-op otherwise — leaves `life[a]` unchanged whenever `b` has no
/// creation channel to `a`. Since creation adds no resources (clean-shell precondition), `life[a]`
/// is the whole creation-touchable part of `obs(a)`, so `obs(a)` is preserved.
proof fn create_preserves_life_a(may_create: Map<Dom, bool>, live: Map<Dom, bool>, b: Dom, a: Dom, t: Dom)
    requires
        b != a,
        !creation_channel(may_create, live, b, a),
    ensures
        life_after_create(live, may_create, b, t)[a] == live[a],
{
    if create_guard(may_create, live, b, t) {
        create_target_not_a(may_create, live, b, a, t);
        // t != a, so inserting `Live` at `t` does not change `life[a]`.
        assert(life_after_create(live, may_create, b, t) == live.insert(t, true));
    } else {
        // Guard failed: the create is a no-op, `life` is untouched.
    }
}

} // verus!
