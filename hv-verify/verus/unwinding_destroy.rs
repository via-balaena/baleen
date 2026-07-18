// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Tier D / Verus — the `DomainDestroy` cascade unwinding lemma (the multi-domain one)
//!
//! The **last** and hardest per-transition local-respect obligation of Tier D — the only
//! *genuinely multi-domain* transition. Every other transition touches the caller's resources
//! and at most one direct partner's; `DomainDestroy(c)` tears `c` down completely and its cleanup
//! **cascades to `c`'s partners** (`hypervisor.rs::domain_destroy`), so a step by `b` (with
//! `controls[b][c]`) can move a *third* domain `a`'s observation. This is the classic
//! **intransitive** non-interference flow the enumerator bridge found
//! (`hv-sim/src/noninterference.rs`, `dropping_teardown_reach_is_caught`); here it is proven
//! ∀-N. With it, **every transition class of Tier D is discharged.** See
//! `docs/TIER-D-NONINTERFERENCE.md`.
//!
//! ## The compound write-set, and why the cascade is the hard one
//!
//! `domain_destroy(c)` runs a sequence of sub-operations that between them touch **three**
//! components of `obs(a)`:
//!
//! * **ports** — `evtchn::close_all(c)` returns `c`'s interdomain peers to `Unbound{c}`, and
//!   `evtchn::clear_unbound_into(c)` frees every `Unbound{c}` port. Touches `a`'s port `p` iff
//!   `p` names `c` (`Interdomain{c}` or `Unbound{c}`) — i.e. **`a` holds a port toward `c`**.
//! * **grant rows** — `grant::revoke_grants_to(c)` clears grants with grantee `c`, and
//!   `grant::drain_maps_of(c)` drops the map-count of any grant `c` had mapped. Touches `a`'s
//!   grant row iff its grantee is `c` — i.e. **`a` granted to `c`**.
//! * **frame references** — `drain_maps_of(c)` releasing `c`'s maps drops the reference count of
//!   any frame `c` had mapped. Touches `a`'s frame iff `c` held a map over it — and a map by `c`
//!   of `a`'s frame exists only if **`a` granted to `c`** (the grant `map`-identity: `map`
//!   checks grantee identity, `grant.rs`).
//!
//! So *every* way the cascade reaches `obs(a)` is conditioned on **`a` granted to `c`** or **`a`
//! holds a port toward `c`** — exactly the non-interference **teardown-reach** term
//! (`noninterference::Channels::teardown_reach`): `∃c: controls[b][c] ∧ (a→c grant ∨ a→c port)`.
//! (The *reverse* direction — `a` referencing `c`'s frames — cannot arise past a *proceeding*
//! destroy: `DomainBusy` refuses teardown while any foreign domain holds a live map of, or a
//! page-table link into, `c`'s frames — `hypervisor.rs:1178`. So a proceeding destroy leaves
//! `a`'s held mappings and `a`'s own frames alone.)
//!
//! ## The finding — the cascade *composes both kinds of channel*
//!
//! The four direct channels split two-and-two (memory/signal borrow from a state invariant;
//! authority/creation come from a guard — `docs/TIER-D-NONINTERFERENCE.md` §5b). The cascade is
//! the **union of both kinds in one transition**: its port and grant-revoke sub-ops are
//! *guard-shaped* (the write is a filtered clear on a directly-readable key — `remote == c`,
//! `grantee == c`), while its drain→frame-reference sub-op *borrows from a relational invariant*
//! (the grant `map`-identity: a map by `c` over `a`'s frame ⟹ `a` granted to `c`). Proving the
//! cascade means proving both shapes and composing them under one channel term.
//!
//! ## What is proven
//!
//! * `port_preserved` — a port not toward `c` is unchanged by the port cascade.
//! * `grant_row_preserved` — a grant row not granting to `c` is unchanged by the grant cascade.
//! * `drain_preserves_frame_refs` — the reference count over a frame is unchanged by draining
//!   `c`'s maps when `c` holds no map over it (a filtered-count-equality, `Seq` induction —
//!   frame-lemma-shaped).
//! * `no_c_map_over_a_frame` — the grant `map`-identity consequence: if `a` granted nothing to
//!   `c`, `c` holds no map over any `a`-owned frame, so the drain touches none of `a`'s frames.
//! * `no_channel_no_reach_to_c` — **the intransitive-channel heart**: if `b` has no authorized
//!   channel to `a` and the destroy of `c` is authorized (`b == c ∨ controls[b][c]`), then `a`
//!   has no reach relationship with `c` (`¬(a→c grant) ∧ ¬(a→c port)`) — so all three
//!   preservation lemmas apply and `obs(a)` is preserved.
//!
//! ## Fidelity & non-vacuity
//!
//! The sub-op models transcribe the teardown functions' effects (`close_all`/`clear_unbound_into`
//! /`revoke_grants_to`/`drain_maps_of`); the enumerator bridge pins the whole cascade on the real
//! `Hypervisor` at small size (the three-domain sweep, where the intransitive flow is live).
//! Non-vacuity (validated, recorded in `README.md`): dropping the `!granted_to` hypothesis from
//! `no_c_map_over_a_frame`, or the reach hypotheses from `no_channel_no_reach_to_c`, makes Verus
//! reject the proof.
//!
//! Run: `verus --crate-type=lib hv-verify/verus/unwinding_destroy.rs` (exit 0 = all proven).

use vstd::prelude::*;

verus! {

/// A domain / frame / port id (`int` — the §2.1 reduction; here ∀ domain **and** partner count,
/// the axis that has no size cutoff, `docs/TIER-B-CUTOFF.md` §2.4).
type Id = int;

// ─── the port cascade (guard-shaped) ────────────────────────────────────────────────

/// An event-channel port, projected to what the cascade reads. `Local` covers `Virq`/`Ipi`
/// (never toward another domain); `Free` is closed.
enum Port {
    Free,
    Unbound(Id),
    Inter(Id, Id),
    Local(Id),
}

/// `a`'s port names `c` — the signal-side reach relationship (`noninterference::a_port_toward`).
spec fn port_toward(p: Port, c: Id) -> bool {
    match p {
        Port::Unbound(r) => r == c,
        Port::Inter(r, _) => r == c,
        _ => false,
    }
}

/// The port cascade's net effect on a **non-`c`** port: `close_all(c)` returns an interdomain
/// peer of `c` (`Inter(c, _)`) to `Unbound(c)`; `clear_unbound_into(c)` frees an `Unbound(c)`
/// port; every other port is untouched. Mirror of `evtchn::close_all` + `clear_unbound_into`.
spec fn port_after_destroy(p: Port, c: Id) -> Port {
    match p {
        Port::Inter(r, q) => if r == c { Port::Unbound(c) } else { Port::Inter(r, q) },
        Port::Unbound(r) => if r == c { Port::Free } else { Port::Unbound(r) },
        Port::Free => Port::Free,
        Port::Local(v) => Port::Local(v),
    }
}

/// A port not toward `c` is untouched by the port cascade — guard-shaped: the write condition
/// (`remote == c`) is exactly the reach relationship, read directly off the port.
proof fn port_preserved(p: Port, c: Id)
    requires
        !port_toward(p, c),
    ensures
        port_after_destroy(p, c) == p,
{
}

// ─── the grant-row cascade (guard-shaped) ───────────────────────────────────────────

/// A grant table row projected to what the cascade reads: its grantee and live map-count. `None`
/// is an inactive slot.
struct GrantRow {
    grantee: Id,
    map_count: int,
}

/// `a` granted to `c` at this row — the consent-side reach relationship
/// (`noninterference::a_grants_to`).
spec fn granted_to(g: Option<GrantRow>, c: Id) -> bool {
    match g {
        Some(r) => r.grantee == c,
        None => false,
    }
}

/// The grant cascade's net effect on `a`'s row: `revoke_grants_to(c)` clears rows with grantee
/// `c`, and `drain_maps_of(c)` drops the map-count of such a row — both touch **only** grantee-`c`
/// rows. Modeled as: a grantee-`c` row ends revoked (`None`); any other row is untouched.
spec fn grant_after_destroy(g: Option<GrantRow>, c: Id) -> Option<GrantRow> {
    match g {
        Some(r) => if r.grantee == c { None } else { Some(r) },
        None => None,
    }
}

/// A grant row not granting to `c` is untouched by the grant cascade — guard-shaped
/// (`grantee == c` read directly).
proof fn grant_row_preserved(g: Option<GrantRow>, c: Id)
    requires
        !granted_to(g, c),
    ensures
        grant_after_destroy(g, c) == g,
{
}

// ─── the drain → frame-reference cascade (borrows from the grant map-identity) ──────

/// The live grant-map population, projected to `(grantee, frame)` — the reference-bearing maps.
/// `drain_maps_of(c)` removes exactly the maps with grantee `c`.
type Maps = Seq<(Id, Id)>;

/// `c` holds a map over frame `f`.
spec fn c_maps_over(maps: Maps, c: Id, f: Id) -> bool {
    exists|i: int| #![trigger maps[i]] 0 <= i < maps.len() && maps[i] == (c, f)
}

/// The reference count a frame `f` carries from grant maps — `|{ maps naming f }|` (mirror of the
/// map-side contribution to `p2m::refs`, the summed live maps over `f`).
spec fn refs_over(maps: Maps, f: Id) -> int
    decreases maps.len(),
{
    if maps.len() == 0 {
        0
    } else {
        refs_over(maps.subrange(0, maps.len() - 1), f) + (if maps[maps.len() - 1].1 == f {
            1int
        } else {
            0int
        })
    }
}

/// The reference count over `f` after `drain_maps_of(c)` removes `c`'s maps — `|{ maps naming f
/// whose grantee ≠ c }|`.
spec fn refs_over_after_drain(maps: Maps, f: Id, c: Id) -> int
    decreases maps.len(),
{
    if maps.len() == 0 {
        0
    } else {
        refs_over_after_drain(maps.subrange(0, maps.len() - 1), f, c) + (if maps[maps.len() - 1].1
            == f && maps[maps.len() - 1].0 != c {
            1int
        } else {
            0int
        })
    }
}

/// **The drain preserves a frame's references when `c` holds no map over it.** Filtered-count
/// equality by `Seq` induction (frame-lemma-shaped): removing `c`'s maps changes the count over
/// `f` only by the number of `(c, f)` maps, which is zero here.
proof fn drain_preserves_frame_refs(maps: Maps, f: Id, c: Id)
    requires
        !c_maps_over(maps, c, f),
    ensures
        refs_over_after_drain(maps, f, c) == refs_over(maps, f),
    decreases maps.len(),
{
    if maps.len() > 0 {
        let prefix = maps.subrange(0, maps.len() - 1);
        assert(!c_maps_over(prefix, c, f)) by {
            assert forall|i: int| #![trigger prefix[i]] 0 <= i < prefix.len() implies prefix[i]
                != (c, f) by {
                assert(prefix[i] == maps[i]);
            }
        }
        drain_preserves_frame_refs(prefix, f, c);
        // The last map is `(c, f)`? No — that would be a `c`-map over `f`, excluded. So it adds
        // the same (0 or 1) to both counts.
        assert(maps[maps.len() - 1] != (c, f));
    }
}

/// **The grant `map`-identity consequence.** A map by `c` over a frame `a` owns exists only if
/// `a` granted to `c` (`grant::map` checks grantee identity). So if `a` granted nothing to `c`,
/// `c` holds no map over any `a`-owned frame — and the drain (via `drain_preserves_frame_refs`)
/// touches none of `a`'s frame references. This is the cascade's *borrows-from-a-relational-
/// invariant* component: the frame-reference locality rests on the map-identity, exactly the
/// #20/#21 shape (contrast the guard-shaped port/grant-row sub-ops above).
proof fn no_c_map_over_a_frame(maps: Maps, owner: spec_fn(Id) -> Id, a: Id, c: Id, f: Id)
    requires
        // map-identity: every live map `(g, frame)` over an `a`-owned frame has `a` granting to
        // `g` — so a map over an `a`-frame by a non-grantee cannot exist. Instantiated at `c`:
        forall|i: int| #![trigger maps[i]]
            0 <= i < maps.len() && owner(maps[i].1) == a && maps[i].0 == c ==> granted_to_some(a, c),
        !granted_to_some(a, c),
        owner(f) == a,
    ensures
        !c_maps_over(maps, c, f),
{
    assert forall|i: int| #![trigger maps[i]] 0 <= i < maps.len() implies maps[i] != (c, f) by {
        if maps[i] == (c, f) {
            assert(owner(maps[i].1) == a && maps[i].0 == c);
        }
    }
}

/// Whether `a` holds *any* active grant to `c` (`∃ gref`). The consent reach relationship at the
/// domain level, used by the map-identity and the channel bookkeeping.
uninterp spec fn granted_to_some(a: Id, c: Id) -> bool;

// ─── the intransitive-channel bookkeeping ───────────────────────────────────────────

/// `a` has a reach relationship with `c`: a grant to `c`, or a port toward `c`. This is the
/// per-target content of the non-interference teardown-reach term.
spec fn reach(a: Id, c: Id, ports_toward: spec_fn(Id, Id) -> bool) -> bool {
    granted_to_some(a, c) || ports_toward(a, c)
}

/// The full authorized-channel relation `b ⇝ a`, projected to what a `DomainDestroy` needs:
/// a direct relationship (self / grant / port / control) **or** the teardown-reach term
/// (`∃c'. controls[b][c'] ∧ reach(a, c')`). Modeled abstractly so the bookkeeping lemma below is
/// about the *structure* of the relation, not its every direct clause.
uninterp spec fn controls(b: Id, c: Id) -> bool;

/// **The intransitive-channel heart.** If `b` has no authorized channel to `a` (in particular no
/// teardown-reach: `∀c'. controls[b][c'] ⟹ ¬reach(a, c')`), and the destroy of `c` is authorized
/// (`b == c ∨ controls[b][c]`) with `b ≠ a`, then `a` has no reach relationship with `c`. Hence
/// every preservation lemma above applies and `obs(a)` is preserved by the cascade.
///
/// The two authority cases: a **peer** destroy (`controls[b][c]`) is excluded directly by the
/// teardown-reach hypothesis; a **self** destroy (`b == c`) reduces `reach(a, c)` to `reach(a, b)`,
/// which the *direct* grant/port channels (also absent under `¬(b ⇝ a)`) rule out.
proof fn no_channel_no_reach_to_c(
    b: Id,
    a: Id,
    c: Id,
    ports_toward: spec_fn(Id, Id) -> bool,
)
    requires
        b != a,
        // ¬ teardown-reach: no controlled domain of `b` is reachable to `a`.
        forall|cc: Id| #![trigger controls(b, cc)] controls(b, cc) ==> !reach(a, cc, ports_toward),
        // ¬ direct grant/port channel to `b` itself (needed for the self-destroy `c == b` case).
        !reach(a, b, ports_toward),
        // the destroy fired: authorized target.
        b == c || controls(b, c),
    ensures
        !reach(a, c, ports_toward),
{
    // Peer destroy: `controls(b, c)` ⟹ `¬reach(a, c)` by the teardown-reach hypothesis.
    // Self destroy: `c == b` ⟹ `reach(a, c) == reach(a, b)`, excluded by the direct hypothesis.
}

} // verus!
