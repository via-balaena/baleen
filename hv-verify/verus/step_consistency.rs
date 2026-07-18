// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Tier D / Verus — closing the last mile: step- & output-consistency
//!
//! The whole-system unwinding theorem (`noninterference_theorem.rs`) proves **Theorem A**
//! (integrity non-interference — *a domain `a` is unaffected by principals that don't interfere
//! with it*) from **local respect** alone, which the five per-transition lemmas fully discharge —
//! that result is airtight and needs nothing here. **Theorem B** (the confidentiality dual — *`a`
//! learns nothing beyond what is authorized to flow to it*) additionally assumes **step
//! consistency**. This file discharges what is cleanly derivable of that premise and **pins down
//! precisely the irreducible residual** — the honest content of "the last mile."
//!
//! ## Two results, and a finding
//!
//! * `step_consistency_off_channel` — **the reduction.** From local respect alone, step
//!   consistency holds for every step whose actor does **not** interfere with `a`: both
//!   successors leave `obs(a)` where it was, so they agree. So the step-consistency *premise* is
//!   never needed off-channel — it reduces to the **interfering-actor** case. This tightens the
//!   assembly: the confidentiality obligation is only ever about authorized flows.
//! * `factored_step_is_consistent` — **the on-channel characterization.** When the successor
//!   `obs(step(s,act), a)` is a function of `obs(s,a)` and the actor's observation
//!   `obs(s, actor(act))` (a `delta`), step consistency follows. This is the shape the **write**
//!   channels have: a principal `b`'s *authorized effect on `a`* — `b` maps a grant `a` offered
//!   (`a`'s frame refs `+1`), `b` signals a channel `a` is party to (`a`'s pending bit set) — is
//!   computed from `a`'s own state and `b`'s, both observed. So step consistency holds for every
//!   *write* (integrity-direction) channel.
//!
//! ## The finding — the residual is the confidentiality *read* direction (obs read-closure)
//!
//! What does **not** factor through `obs(a) + obs(actor)` is a domain reading a *partner's* state
//! it is authorized to see — `a` itself mapping/copying a grant a partner `c` offered it, whose
//! success reads `c`'s frame ownership (`StaleGrant`) — state in neither `obs(a)` nor `obs(actor
//! == a)`. This is the exact dual of local respect: local respect is *integrity* (no unauthorized
//! principal **writes** `obs(a)`), and it is **proven, ∀-N**; the residual is *confidentiality*
//! (no unauthorized state is **read** into `a`'s view). Discharging it fully requires refining the
//! observation to its **read-closure** — `obs(a)` extended with the partner state `a` holds a
//! read-capability for (the frames behind grants `a` has mapped) — after which the read factors
//! and step consistency closes. That refinement (and re-validating the channel relation against
//! it) is a bounded next arc, *scoped here rather than papered over*; the integrity property the
//! tier set out to prove (`Theorem A`) stands complete without it.
//!
//! ## Output consistency
//!
//! Identical shape: a domain's own hypercall **result** (`HvOutcome`/`HvError`) is a function of
//! `obs(a)` for `a`-local ops, and factors through `obs(a) + obs(partner)` for cross-domain ones —
//! the same read-closure closes it. `output_consistency_off_channel` records the derivable half
//! (a non-interfering actor's step changes none of `a`'s outputs-determining state).
//!
//! ## Non-vacuity
//!
//! Dropping `local_respect()` from `step_consistency_off_channel`, or the `delta`-factoring
//! hypothesis from `factored_step_is_consistent`, makes Verus reject the proof (recorded in
//! `hv-verify/verus/README.md`).
//!
//! Run: `verus --crate-type=lib hv-verify/verus/step_consistency.rs` (exit 0 = all proven).

use vstd::prelude::*;

verus! {

type State = int;
type Act = int;
type Dom = int;

uninterp spec fn obs(s: State, a: Dom) -> int;

uninterp spec fn step(s: State, act: Act) -> State;

uninterp spec fn actor(act: Act) -> Dom;

uninterp spec fn interferes(s: State, b: Dom, a: Dom) -> bool;

/// Local respect — proven ∀-N by the five per-transition lemmas (`frame_lemma.rs` …
/// `unwinding_destroy.rs`): a step by a principal with no authorized channel to `a` leaves
/// `obs(a)` unchanged.
spec fn local_respect() -> bool {
    forall|s: State, act: Act, a: Dom|
        actor(act) != a && !interferes(s, actor(act), a) ==> #[trigger] obs(step(s, act), a) == obs(
            s,
            a,
        )
}

/// **The reduction.** From local respect alone, step consistency holds whenever the actor does
/// not interfere with `a`: local respect fixes `obs(a)` on both sides, so two states agreeing on
/// `obs(a)` still agree after the step. So the step-consistency *premise* of the unwinding theorem
/// is only ever needed for **interfering** actors — the confidentiality obligation is exactly, and
/// only, about authorized flows.
proof fn step_consistency_off_channel(s: State, t: State, act: Act, a: Dom)
    requires
        local_respect(),
        obs(s, a) == obs(t, a),
        actor(act) != a,
        !interferes(s, actor(act), a),
        !interferes(t, actor(act), a),
    ensures
        obs(step(s, act), a) == obs(step(t, act), a),
{
    // local respect: obs(step(s,act),a) == obs(s,a) and obs(step(t,act),a) == obs(t,a); equal.
}

/// The successor's `obs(a)` as a function of `obs(a)` and the actor's observation — the "delta" a
/// **write** channel applies (a principal's authorized effect on `a`, computed from `a`'s state
/// and the actor's).
uninterp spec fn delta(obs_a: int, obs_actor: int) -> int;

/// `act`'s effect on `obs(a)` **factors** through `obs(a)` and the actor's observation — the shape
/// every write (integrity-direction) channel has.
spec fn writes_factor(act: Act, a: Dom) -> bool {
    forall|s: State|
        #[trigger] obs(step(s, act), a) == delta(obs(s, a), obs(s, actor(act)))
}

/// **The on-channel characterization.** If a step's effect on `obs(a)` factors through `obs(a)`
/// and the actor's observation, step consistency follows: two states agreeing on both compute the
/// same `delta`. This discharges step consistency for every **write** channel — the
/// integrity-direction flows, where a principal's authorized effect on `a` is a function of the
/// two observations. (The residual is the *read* direction; see the module docs.)
proof fn factored_step_is_consistent(s: State, t: State, act: Act, a: Dom)
    requires
        writes_factor(act, a),
        obs(s, a) == obs(t, a),
        obs(s, actor(act)) == obs(t, actor(act)),
    ensures
        obs(step(s, act), a) == obs(step(t, act), a),
{
    // Both successors equal `delta(obs(·,a), obs(·,actor))`, and the arguments agree.
}

/// Whether `a`'s hypercall outputs are determined by `obs(a)` in state `s` — the output-side
/// projection (`HvOutcome`/`HvError` a call by `a` would return). Uninterpreted: the concrete
/// instantiation reads `a`'s own resources; for `a`-local ops it is `obs(a)`-determined.
uninterp spec fn out_state(s: State, a: Dom) -> int;

/// **Output consistency — the derivable half.** A step by a principal that does not interfere with
/// `a` leaves `a`'s output-determining state where local respect leaves `obs(a)`: unchanged. So a
/// non-interfering actor cannot change what `a`'s own hypercalls return — the output-side analogue
/// of `step_consistency_off_channel`. (Modeled by tying `out_state` to `obs` off-channel, the
/// faithful reading: `a`'s outputs are a projection of `a`'s observation.)
proof fn output_consistency_off_channel(s: State, t: State, act: Act, a: Dom)
    requires
        local_respect(),
        obs(s, a) == obs(t, a),
        actor(act) != a,
        !interferes(s, actor(act), a),
        !interferes(t, actor(act), a),
        // `a`'s outputs are a function of `obs(a)` (the projection the enumerator bridge checks).
        forall|u: State, v: State| obs(u, a) == obs(v, a) ==> #[trigger] out_state(u, a)
            == #[trigger] out_state(v, a),
    ensures
        out_state(step(s, act), a) == out_state(step(t, act), a),
{
    // local respect fixes obs(step(·,act),a) to obs(·,a), which agree; outputs follow obs.
}

} // verus!
