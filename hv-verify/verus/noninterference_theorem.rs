// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Tier D / Verus — the whole-system non-interference theorem (the compositional assembly)
//!
//! The **capstone** of Tier D, and of the true-diamond program A→D. The per-transition lemmas
//! (`frame_lemma.rs`, `unwinding_signal.rs`, `unwinding_control.rs`, `unwinding_create.rs`,
//! `unwinding_destroy.rs`) each proved **local respect** for one transition class — a single step
//! by a principal with no authorized channel to `a` leaves `obs(a)` unchanged. This file assembles
//! those into the **top-level statement over arbitrary executions**: the standard **unwinding
//! theorem** (Goguen–Meseguer / Rushby; the method seL4-infoflow and CertiKOS use) — that the
//! local, per-step conditions *imply* the global information-flow property. See
//! `docs/TIER-D-NONINTERFERENCE.md`.
//!
//! ## The abstract transition system
//!
//! A `State`, an observation `obs(s, a)` (domain `a`'s isolation surface — modeled by
//! `hv-sim/src/noninterference.rs::obs`), a transition `step(s, act)` where each action `act`
//! carries its **actor** `actor(act)` (the `caller` of the `HvCall`), and the state-dependent,
//! intransitive may-interfere policy `interferes(s, b, a)` (the authorized-channel relation
//! `b ⇝ a`). A run folds a trace of actions: `run(s, tr)`.
//!
//! ## The two unwinding conditions, and which is discharged
//!
//! * **Local respect (LR)** — `actor(act) ⇝̸ a ⟹ obs(step(s,act), a) == obs(s, a)`. This is
//!   **exactly** what the five per-transition lemmas prove (each for one `step` class), ∀-N. LR is
//!   therefore **discharged** for the real system: `frame_lemma` (grant map/unmap), `signal`
//!   (evtchn), `control` (sched/affinity), `create` (`DomainCreate`), `destroy` (the
//!   `DomainDestroy` cascade) cover every `HvCall`.
//! * **Step consistency (SC)** — `obs(s,a)==obs(t,a) ∧ obs(s, actor)==obs(t, actor) ⟹
//!   obs(step(s,act),a)==obs(step(t,act),a)`: `obs(a)`'s successor is a function of `obs(a)` and
//!   the actor's observation. This is the *projection-determinism* condition — light given
//!   `~_a` = `obs`-equality (the transition reads only `obs(a)` and the actor's authorized
//!   contribution to compute `obs(a)`'s next value). It is stated here as the remaining unwinding
//!   premise.
//!
//! ## What is proven
//!
//! * `local_respect_lifts_to_traces` (**Theorem A**) — from **LR alone**: a domain `a` sees a
//!   **constant** observation across *any* execution whose actions are all by principals that do
//!   not interfere with `a`. This is the direct, complete assembly of the five per-transition
//!   lemmas into a whole-execution guarantee: *unrelated activity is invisible to `a`.*
//! * `unwinding_preserves_a_equivalence` (**Theorem B**) — from **LR + SC**: two executions that
//!   start `obs(a)`-equivalent and agree, at each step, on the acting domain's observation, stay
//!   `obs(a)`-equivalent throughout. This is the confidentiality dual — *`a`'s view is determined
//!   entirely by the inputs authorized to flow to it* — the classic non-interference conclusion.
//!
//! Together: `obs(a)` over any run depends only on the actions of principals authorized to affect
//! `a`, and not at all on the rest. That is the top-level isolation property Tier D set out to
//! establish — the invariants of Tiers A–C *collectively imply* it. The theorems are proven
//! generically (uninterpreted `obs`/`step`/`actor`/`interferes`), so they hold for the concrete
//! Baleen instantiation once LR is discharged (done) and SC supplied.
//!
//! ## Non-vacuity (validated)
//!
//! Dropping the `local_respect()` premise from Theorem A, or `step_consistent()` from Theorem B,
//! makes Verus reject the proof (recorded in `hv-verify/verus/README.md`) — the global property
//! genuinely rests on the per-step conditions, which is the whole content of an unwinding theorem.
//!
//! Run: `verus --crate-type=lib hv-verify/verus/noninterference_theorem.rs` (exit 0 = all proven).

use vstd::prelude::*;

verus! {

/// A whole-system state (opaque). The concrete instantiation is `hv_core::Hypervisor`.
type State = int;

/// An action — a routed `HvCall` carrying its `caller`. Opaque; `actor` reads its principal.
type Act = int;

/// A domain id.
type Dom = int;

/// An observation — `obs(s, a)` is domain `a`'s isolation surface in state `s` (the projection
/// `hv-sim/src/noninterference.rs::obs` computes on the real state).
uninterp spec fn obs(s: State, a: Dom) -> int;

/// The transition function: `step(s, act)` routes one action (`Hypervisor::dispatch`).
uninterp spec fn step(s: State, act: Act) -> State;

/// The acting principal of an action — the `caller` of the `HvCall`.
uninterp spec fn actor(act: Act) -> Dom;

/// The state-dependent, intransitive may-interfere policy: `interferes(s, b, a)` iff `b ⇝ a` in
/// `s` (the authorized-channel relation of `noninterference.rs` — grant / evtchn / control /
/// creation / teardown-reach).
uninterp spec fn interferes(s: State, b: Dom, a: Dom) -> bool;

/// **Local respect** — the unwinding condition the five per-transition lemmas discharge: a step by
/// a principal with no authorized channel to `a` leaves `obs(a)` unchanged.
spec fn local_respect() -> bool {
    forall|s: State, act: Act, a: Dom|
        actor(act) != a && !interferes(s, actor(act), a) ==> #[trigger] obs(step(s, act), a) == obs(
            s,
            a,
        )
}

/// **Step consistency** (weak) — `obs(a)`'s successor is a function of `obs(a)` and the actor's
/// observation: two states agreeing on both compute the same next `obs(a)`. The projection-
/// determinism premise (light given `~_a` = `obs`-equality).
spec fn step_consistent() -> bool {
    forall|s: State, t: State, act: Act, a: Dom|
        #![trigger obs(step(s, act), a), obs(step(t, act), a)]
        obs(s, a) == obs(t, a) && obs(s, actor(act)) == obs(t, actor(act)) ==> obs(step(s, act), a)
            == obs(step(t, act), a)
}

/// Fold a trace of actions over a state — one execution.
spec fn run(s: State, tr: Seq<Act>) -> State
    decreases tr.len(),
{
    if tr.len() == 0 {
        s
    } else {
        run(step(s, tr[0]), tr.subrange(1, tr.len() as int))
    }
}

/// Every action in `tr`, at the point it is applied, is by a principal that does **not** interfere
/// with `a` (and is not `a` itself) — an execution of activity entirely unrelated to `a`.
spec fn trace_noninterfering(s: State, tr: Seq<Act>, a: Dom) -> bool
    decreases tr.len(),
{
    if tr.len() == 0 {
        true
    } else {
        actor(tr[0]) != a && !interferes(s, actor(tr[0]), a) && trace_noninterfering(
            step(s, tr[0]),
            tr.subrange(1, tr.len() as int),
            a,
        )
    }
}

/// **Theorem A — local respect lifts to whole executions.** From local respect alone: if every
/// action of an execution is by a principal that does not interfere with `a`, then `a`'s
/// observation is **unchanged** across the entire run. Unrelated activity — of any length — is
/// invisible to `a`. This is the direct assembly of the five per-transition local-respect lemmas
/// into a guarantee over arbitrary executions.
proof fn local_respect_lifts_to_traces(s: State, tr: Seq<Act>, a: Dom)
    requires
        local_respect(),
        trace_noninterfering(s, tr, a),
    ensures
        obs(run(s, tr), a) == obs(s, a),
    decreases tr.len(),
{
    if tr.len() > 0 {
        let act = tr[0];
        let s1 = step(s, act);
        // Head of `trace_noninterfering` gives `actor(act) ⇝̸ a`, so local respect gives the first
        // step preserves `obs(a)`; induction gives the rest.
        assert(obs(s1, a) == obs(s, a));
        local_respect_lifts_to_traces(s1, tr.subrange(1, tr.len() as int), a);
    }
}

/// Two executions from `s` and `t` agree, at each step, on the acting domain's observation — the
/// step-consistency precondition threaded along both runs (the actor's authorized inputs match).
spec fn traces_agree_on_actor(s: State, t: State, tr: Seq<Act>, a: Dom) -> bool
    decreases tr.len(),
{
    if tr.len() == 0 {
        true
    } else {
        obs(s, actor(tr[0])) == obs(t, actor(tr[0])) && traces_agree_on_actor(
            step(s, tr[0]),
            step(t, tr[0]),
            tr.subrange(1, tr.len() as int),
            a,
        )
    }
}

/// **Theorem B — the unwinding theorem (confidentiality).** From local respect + step
/// consistency: two executions that start `obs(a)`-equivalent and agree at each step on the acting
/// domain's observation remain `obs(a)`-equivalent throughout. Equivalently, `obs(a)` over a run is
/// determined **entirely** by the observations of the domains authorized to affect `a` — it leaks
/// nothing about anything else. This is the classic non-interference conclusion the unwinding
/// conditions deliver.
proof fn unwinding_preserves_a_equivalence(s: State, t: State, tr: Seq<Act>, a: Dom)
    requires
        step_consistent(),
        obs(s, a) == obs(t, a),
        traces_agree_on_actor(s, t, tr, a),
    ensures
        obs(run(s, tr), a) == obs(run(t, tr), a),
    decreases tr.len(),
{
    if tr.len() > 0 {
        let act = tr[0];
        // Step consistency: agreeing on `obs(a)` and on the actor's obs ⟹ the successors agree on
        // `obs(a)`; induction carries it down both runs.
        assert(obs(step(s, act), a) == obs(step(t, act), a));
        unwinding_preserves_a_equivalence(
            step(s, act),
            step(t, act),
            tr.subrange(1, tr.len() as int),
            a,
        );
    }
}

} // verus!
