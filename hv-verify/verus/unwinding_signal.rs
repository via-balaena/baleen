// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Tier D / Verus — the signal-channel unwinding lemma (event-channel local respect)
//!
//! The Tier-D *spike* on the deductive (∀-N) axis: one **unwinding lemma** proven end-to-end,
//! to establish that non-interference's local-respect condition has the same tractable,
//! *"borrows-from-a-relational-invariant"* shape the Tier-C obligations had — on a **second
//! seam** (`frame_lemma.rs` already discharged the memory channel; this is the event-channel
//! one), so the pattern is shown to generalize across the observation, not to be a one-off.
//!
//! ## What local respect needs here
//!
//! `obs(a)` (`hv-sim/src/noninterference.rs`) includes `a`'s event-channel ports and their
//! **pending** bits. The one transition that sets a *foreign* port's pending bit is
//! `EvtchnSend`: `send(b, p)` sets pending on `send_target(b, p)` — for an `Interdomain` port
//! that is the **peer** the port names (`evtchn.rs::send_target`). So a step by `b` can move
//! `obs(a)`'s pending bits only if `b` holds a port whose peer is one of `a`'s ports.
//!
//! The non-interference **channel relation** (`noninterference.rs`) is stated on `a`'s side:
//! `b ⇝ a` via the signal channel iff **`a`** holds a port toward `b`. The transition acts
//! from **`b`**'s side (`b`'s port toward `a`). Local respect therefore requires bridging the
//! two sides — and the bridge is exactly the event-channel **reciprocity** invariant
//! (`evtchn.rs::first_violation`, `ReciprocityBroken`): an `Interdomain` port's peer is an
//! `Interdomain` port back to it. This is the same shape as design-lessons #20/#21 — the
//! signal locality **borrows from a relational invariant** (reciprocity), one seam over.
//!
//! ## What is proven
//!
//! Model the interdomain links as a partial map `peer: (dom,port) ↦ (dom,port)` holding
//! exactly the `Interdomain` ports (a port not in the map is `Free`/`Unbound`/`Virq`/`Ipi` —
//! none of which `send` can target across domains). Reciprocity is that `peer` is an
//! **involution** (`peer[peer[k]] == k`).
//!
//! * `no_port_toward_is_symmetric` — **the deductive heart.** Under reciprocity, if `a` holds
//!   no port toward `b`, then `b` holds no port toward `a`. (Contrapositive: a `b`-port toward
//!   `a` has, by the involution, a reverse `a`-port toward `b`.) This is the two-sides bridge.
//! * `send_by_b_misses_a` — a concrete send: if `b` holds no port toward `a`, then for every
//!   port `b` could send on, the target port does not belong to `a` — so setting the target's
//!   pending bit leaves every one of `a`'s pending bits unchanged. `obs(a)`'s signal
//!   projection is preserved by a step from a `b` with no signal channel to `a`.
//!
//! ## Fidelity (a mirror, managed — same discipline as `frame_lemma.rs`)
//!
//! `peer` mirrors the `Interdomain { remote, remote_port }` links `evtchn.rs` stores;
//! `involution` mirrors the `ReciprocityBroken` check (`first_violation`); `send_target`
//! mirrors `evtchn.rs::send_target` for the interdomain case. The **enumerator bridge**
//! (`hv-sim/src/noninterference.rs`, `local_respect_holds_on_real_code`) already checks this
//! very local-respect condition on the *real* `Hypervisor` over every reachable small state —
//! Verus adds the ∀-N (arbitrary port population) step, exactly the enumerator/Verus split of
//! Tier C.
//!
//! ## Non-vacuity (validated)
//!
//! Dropping the involution (reciprocity) hypothesis from `no_port_toward_is_symmetric` makes
//! Verus reject it — the bridge genuinely rests on reciprocity, not on the shape of the map.
//! (Recorded in `hv-verify/verus/README.md`.)
//!
//! Run: `verus --crate-type=lib hv-verify/verus/unwinding_signal.rs` (exit 0 = all proven).

use vstd::prelude::*;

verus! {

/// A port coordinate `(domain, port index)`. ids are `int` (the §2.1 reduction: only sizes
/// matter, so the unbounded integer domain is the honest ∀-size model).
type Coord = (int, int);

/// The interdomain-link map: `peer[(d,p)] == (r,q)` iff `(d,p)` is an `Interdomain` port whose
/// remote peer is `(r,q)`. A coordinate absent from the map is a non-interdomain port
/// (`Free`/`Unbound`/`Virq`/`Ipi`), which `send` cannot target across a domain boundary.
/// Mirror of the `Interdomain { remote, remote_port }` links `evtchn.rs` stores.
type Peers = Map<Coord, Coord>;

/// **Reciprocity** (`evtchn.rs::first_violation`, `ReciprocityBroken`): every interdomain
/// port's peer is itself an interdomain port pointing back — the map is an **involution** on
/// its domain. This is the relational invariant the signal locality borrows from.
spec fn involution(peer: Peers) -> bool {
    forall|k: Coord| #![trigger peer[k]]
        peer.dom().contains(k) ==> peer.dom().contains(peer[k]) && peer[peer[k]] == k
}

/// `a` holds a port toward `b`: some interdomain port owned by domain `a` whose peer lies in
/// domain `b`. This is the non-interference channel relation's signal term, stated on `a`'s
/// side (`noninterference.rs::a_port_toward`).
spec fn holds_port_toward(peer: Peers, a: int, b: int) -> bool {
    exists|p: int| #![trigger peer[(a, p)]]
        peer.dom().contains((a, p)) && (peer[(a, p)]).0 == b
}

/// The target port a `send` on `(d, p)` would set pending: the peer, for an interdomain port
/// (mirror of `evtchn.rs::send_target`, interdomain case). `None` for a non-interdomain port
/// (`send` rejects `Unbound`/`Virq`/`Free`; an `Ipi` targets its own domain, never a peer).
spec fn send_target(peer: Peers, d: int, p: int) -> Option<Coord> {
    if peer.dom().contains((d, p)) {
        Some(peer[(d, p)])
    } else {
        None
    }
}

/// **The deductive heart.** Under reciprocity, "holds a port toward" is symmetric in the sense
/// that its *absence* transfers between the two sides: if `a` holds no port toward `b`, then
/// `b` holds no port toward `a`. This is the two-sides bridge local respect needs — the
/// channel relation is stated on `a`'s ports, the `send` transition acts from `b`'s ports, and
/// reciprocity is what aligns them. Contrapositive: a `b`-port toward `a` has, by the
/// involution, a reverse `a`-port toward `b`.
proof fn no_port_toward_is_symmetric(peer: Peers, a: int, b: int)
    requires
        involution(peer),
        !holds_port_toward(peer, a, b),
    ensures
        !holds_port_toward(peer, b, a),
{
    // Suppose `b` holds a port toward `a`, at `(b, q)` with peer `(a, p2)`. By the involution
    // the peer of `(a, p2)` is `(b, q)`, so `a` holds a port toward `b` at `(a, p2)` —
    // contradicting the hypothesis. Verus discharges the existential witness automatically
    // once the involution fact at `(b, q)` is in scope.
    assert forall|q: int| #![trigger peer[(b, q)]]
        peer.dom().contains((b, q)) implies (peer[(b, q)]).0 != a by {
        if peer.dom().contains((b, q)) {
            let target = peer[(b, q)];
            // involution at (b,q): peer[target] == (b,q), and target is in the domain.
            assert(peer.dom().contains(target) && peer[target] == (b, q));
            if target.0 == a {
                // Then (a, target.1) is an `a`-port whose peer is (b,q), in domain b —
                // exactly `holds_port_toward(peer, a, b)`, the contradiction.
                assert(peer.dom().contains((a, target.1)) && (peer[(a, target.1)]).0 == b);
                assert(holds_port_toward(peer, a, b));
            }
        }
    }
}

/// **A concrete send misses `a`.** If `b` holds no port toward `a`, then every port `b` could
/// send on targets a port *not* owned by `a` — so applying the send (which sets pending at the
/// target) changes no pending bit of any `a` port, and `obs(a)`'s signal projection is
/// preserved. The hypothesis is `a`-side (the channel relation); reciprocity lifts it to the
/// `b`-side send via `no_port_toward_is_symmetric`.
proof fn send_by_b_misses_a(peer: Peers, a: int, b: int, p: int)
    requires
        involution(peer),
        a != b,
        !holds_port_toward(peer, a, b),
    ensures
        // If `(b, p)` is an interdomain port — the only kind `send` can target across a domain
        // boundary — its target does not lie in `a`'s domain, so setting the target's pending
        // bit changes no pending bit of any `a` port. (`send_target(peer, b, p)` is `None` for
        // any other port kind, which trivially touches no `a` port.)
        peer.dom().contains((b, p)) ==> (peer[(b, p)]).0 != a,
{
    no_port_toward_is_symmetric(peer, a, b);
    // `b` now holds no port toward `a`. So if `(b, p)` is interdomain, its peer is not in
    // domain `a` — else `b` would hold a port toward `a`, which we just excluded.
    if peer.dom().contains((b, p)) && (peer[(b, p)]).0 == a {
        assert(holds_port_toward(peer, b, a));
    }
}

} // verus!
