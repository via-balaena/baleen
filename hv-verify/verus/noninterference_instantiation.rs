// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Tier D / Verus — the concrete non-interference INSTANTIATION (closing the paper composition)
//!
//! `noninterference_theorem.rs` proves the generic **unwinding theorem** (Goguen–Meseguer /
//! Rushby) over *uninterpreted* `obs`/`step`/`actor`/`interferes`, taking `local_respect()` and
//! `step_consistent()` as **premises** (`requires`). The five per-transition lemmas
//! (`frame_lemma.rs`, `unwinding_{signal,control,create,destroy}.rs`) and the read-closure
//! (`read_closure.rs`) each prove a *fragment* of those premises — but over their **own**
//! independent `uninterp` symbols. Nothing in Verus tied the fragments to the meta-theorem's
//! premises: the composition ("the five lemmas discharge `local_respect()`; §5e+§5f give
//! `step_consistent()`") lived only in **doc comments** (`docs/TIER-D-NONINTERFERENCE.md`
//! §5d–§5f). `step_consistent()` in particular was a bare `requires` never discharged for any
//! concrete system — the review's **GAP-C**.
//!
//! This file closes that gap. It defines a **concrete** transition system — a composite `Sys`
//! state, an interpreted `obs`/`step`/`actor`/`interferes` — and proves `local_respect()` and
//! `step_consistent()` as **theorems** (`local_respect_holds`, `step_consistent_holds`), then
//! re-runs the unwinding induction over the concrete definitions (`ni_theorem_a`, `ni_theorem_b`)
//! with **no free premise**. The conclusion — `obs(a)` over any run depends only on principals
//! authorized to affect `a`, integrity *and* confidentiality — now stands as a closed Verus
//! obligation, not a hand-composition.
//!
//! ## Scope of this file (four of the five transition classes; DomainDestroy is the follow-on)
//!
//! `Trans` currently models **four** of the five Tier-D transition classes: `Create` (creation),
//! `Send` (signal), `GrantMap` (consent + the confidentiality read-closure), and `SetAffinity`
//! (authority). Both unwinding conditions are discharged, and both trace theorems are premise-free,
//! for exactly these. The fifth — the **`DomainDestroy` cascade**, the sole genuinely multi-domain
//! transition (`unwinding_destroy.rs`) — touches four `obs` components at once (ports, grant rows,
//! a frame-refs drain, and the read-caps) and carries the intransitive teardown-reach term; it is a
//! focused follow-on that extends `Trans`/`step`/`interferes` and the two `*_holds` proofs the same
//! way each class here does. Composing the read-closure with teardown surfaced a further refinement
//! (destroying `a`'s *grantor* alters `obs⁺(a)`, so teardown-reach needs a read-direction term) —
//! recorded for that arc.
//!
//! ## What this closes, and what it deliberately does NOT claim (the altitude discipline)
//!
//! This file closes the **composition** gap: the generic premises are now discharged for a
//! concrete carrier. It does **not** re-derive that the carrier mirrors the real `Hypervisor` —
//! that fidelity is the enumerator bridge's job (`hv-sim/src/noninterference.rs`,
//! `local_respect_holds_on_real_code`), which checks the very same `obs`/channel relation on the
//! real code at bounded size and stays the load-bearing tie to what runs. `Sys` models each obs
//! component and each transition class at exactly the granularity the corresponding fragment
//! lemma uses (each already non-vacuously validated). So the honest reading is: **fragments mirror
//! real code (bridge) + fragments compose to the premises (this file, ∀-N) + premises imply
//! whole-run NI (the meta-theorem)** — three machine-checked links, no prose seam between them.
//!
//! ## The `obs`-refinement forced by GAP-C (a finding, not a free choice)
//!
//! Discharging `step_consistent()` for the **creation** channel forced a correction to the `obs`
//! definition the design doc gave (§2.1 excluded *authority* — `may_create`, the `controls`
//! matrix — from `obs(a)`). A creation flips `life[a]` iff `may_create[creator]`; under the
//! authority-excluding `obs`, that bit is in neither `obs(a)` nor `obs(creator)`, so two runs
//! agreeing on the documented observation diverge in `a`'s view — **Theorem B is false for the
//! documented `obs`.** Verus rejects `step_consistent()` for it (recorded, and reproducible by
//! deleting the `maycreate` field of `Obs` below). The fix, forced by the proof: a domain observes
//! its **own** authority (`may_create[a] ∈ obs(a)`, and the analogous `controls[·][a]` for the
//! affinity channel). This is a genuine model-fidelity correction the paper composition hid; the
//! design doc §2.1 is updated to match.
//!
//! Run: `verus --crate-type=lib hv-verify/verus/noninterference_instantiation.rs` (exit 0 = all
//! proven).

use vstd::prelude::*;
use vstd::assert_maps_equal;

verus! {

/// A domain id (the security principal). `int` is the ∀-N honest domain (only identity/size
/// matters — the §2.1 reduction used throughout the Tier-D corpus).
type Dom = int;

/// An event-channel port coordinate `(domain, port index)`.
type Coord = (Dom, int);

/// The key predicate "coordinate belongs to domain `a`" — used to project the (finite) global
/// port map / pending set down to `a`'s isolation surface (`Set::filter` / `Map::filter_keys`).
pub open spec fn owned_by(a: Dom) -> spec_fn(Coord) -> bool {
    |c: Coord| c.0 == a
}

// ============================================================================================
// The concrete state.  `Sys` grows one group of fields per transition class as the
// instantiation is assembled; this slice models the LIFECYCLE/CREATION surface.
// ============================================================================================

/// The composite whole-system state, projected to what `obs` and the transition classes read.
/// (Mirror of the `Hypervisor` fields the enumerator's `obs` and the five fragment models read.)
pub struct Sys {
    /// The set of **live** domains — `live.contains(a)` is `life[a]` (`hv-core` lifecycle).
    pub live: Set<Dom>,
    /// The set of domains holding **creation authority** — `maycreate.contains(b)` is
    /// `may_create[b]`. Authority over the *creation* channel.
    pub maycreate: Set<Dom>,
    /// The **interdomain-link map**: `peer[(d,p)] == (r,q)` iff port `(d,p)` is an `Interdomain`
    /// port whose remote peer is `(r,q)`. A coordinate absent from the map is a non-interdomain
    /// port (`Free`/`Unbound`/`Virq`/`Ipi`), which `send` cannot target across a domain boundary.
    /// Mirror of the `Interdomain { remote, remote_port }` links `evtchn.rs` stores
    /// (`unwinding_signal.rs`).
    pub peer: Map<Coord, Coord>,
    /// The set of ports with their **pending** bit set. `EvtchnSend` sets pending at the send
    /// target (`evtchn.rs::send_target`).
    pub pending: Set<Coord>,
    /// The **grant table**, keyed by grant id: `grants[g]` is one grant entry (`grant.rs`).
    pub grants: Map<int, GrantRec>,
    /// Frame ownership: `owner[f]` is the domain that owns machine frame `f` (`p2m`).
    pub owner: Map<int, Dom>,
    /// Per-frame **reference count** — `refs[f]` (moved `+1` when a peer maps a grant over `f`).
    pub refs: Map<int, nat>,
    /// The **control matrix** as a set of edges: `controls.contains((b, a))` iff `b` controls `a`
    /// (`b` may set `a`'s vCPU affinity, or destroy `a`). Authority over the *control* channel.
    pub controls: Set<(Dom, Dom)>,
    /// vCPU ownership: `vowner[v]` is the domain owning vCPU `v` (`sched`).
    pub vowner: Map<int, Dom>,
    /// Per-vCPU **affinity mask** — `vaff[v]` (moved by `SchedSetAffinity`).
    pub vaff: Map<int, nat>,
}

/// One grant-table entry, projected to what the memory channel and the read-closure read: the
/// `grantor` (the frame's owner), the `grantee` (who may map it), the `frame`, whether the grant
/// is `active`, and its live-map `count` (`map_count`). Mirror of `grant.rs`'s entry.
pub struct GrantRec {
    pub grantor: Dom,
    pub grantee: Dom,
    pub frame: int,
    pub active: bool,
    pub count: nat,
}

// ============================================================================================
// Actions.  `Trans` grows one variant per transition class; this slice has DomainCreate.
// ============================================================================================

/// A routed hypercall carrying its acting principal (the `caller`), the one fact that makes
/// non-interference *expressible* (design doc §1). One variant per transition class.
pub enum Trans {
    /// `DomainCreate` — `creator` brings `target` to life (guarded by `may_create[creator]` and
    /// `target` being `Dead`). Writes only `life[target]` (a fresh slot adds no resources —
    /// `DeadDomainNotClean`; `unwinding_create.rs`).
    Create { creator: Dom, target: Dom },
    /// `EvtchnSend` — `sender` sends on its port `(sender, port)`, setting the **pending** bit on
    /// the send target: the interdomain peer if the port is `Interdomain` (mirror of
    /// `evtchn.rs::send_target`), else a port in `sender`'s own domain (`Ipi`/`Virq`). The one
    /// transition that can set a *foreign* domain's pending bit (`unwinding_signal.rs`).
    Send { sender: Dom, port: int },
    /// `GrantMap` — `mapper` maps grant `g` (of which it is the `grantee`), incrementing the
    /// grant's live-map `count` and the reference count of the grantor's `frame`. Guarded by the
    /// grant being active, `mapper` being the grantee, and the frame still owned by the grantor
    /// (the `StaleGrant` check). Moves the *grantor*'s frame refs and grant row — the **consent**
    /// (memory) channel (`frame_lemma.rs`); when the mapper is the grantee itself, its *success*
    /// reads the grantor's frame ownership — the **read** direction (`read_closure.rs`).
    GrantMap { mapper: Dom, g: int },
    /// `SchedSetAffinity` — `caller` sets vCPU `vcpu`'s affinity to `aff`. Guarded by
    /// `caller == vowner[vcpu] ∨ controls[caller][vowner[vcpu]]` — the write-restriction *is* the
    /// authorization guard (design-lesson #9; `unwinding_control.rs`). The **authority** channel.
    SetAffinity { caller: Dom, vcpu: int, aff: nat },
}

/// The acting principal of an action — the `caller` of the `HvCall`.
pub open spec fn actor(t: Trans) -> Dom {
    match t {
        Trans::Create { creator, .. } => creator,
        Trans::Send { sender, .. } => sender,
        Trans::GrantMap { mapper, .. } => mapper,
        Trans::SetAffinity { caller, .. } => caller,
    }
}

/// The `SchedSetAffinity` guard: `vcpu` exists and `caller` is its owner or a controller of its
/// owner (the write-restriction that authorizes the affinity change; design-lesson #9).
pub open spec fn set_affinity_guard(s: Sys, caller: Dom, vcpu: int) -> bool {
    &&& s.vowner.dom().contains(vcpu)
    &&& (caller == s.vowner[vcpu] || s.controls.contains((caller, s.vowner[vcpu])))
}

/// The `GrantMap` guard: `g` is a grant, `mapper` is its grantee, it is active, and its frame is
/// still owned by the grantor (the `StaleGrant` ownership read).
pub open spec fn grant_map_guard(s: Sys, mapper: Dom, g: int) -> bool {
    &&& s.grants.dom().contains(g)
    &&& s.grants[g].grantee == mapper
    &&& s.grants[g].active
    &&& s.owner.dom().contains(s.grants[g].frame)
    &&& s.owner[s.grants[g].frame] == s.grants[g].grantor
}

/// The target coordinate a `send` on `(sender, port)` sets pending: the interdomain peer if the
/// port is in the link map, else the port itself (a self-directed `Ipi`/`Virq`, never foreign).
/// Mirror of `evtchn.rs::send_target` (`unwinding_signal.rs`).
pub open spec fn send_target(s: Sys, sender: Dom, port: int) -> Coord {
    if s.peer.dom().contains((sender, port)) {
        s.peer[(sender, port)]
    } else {
        (sender, port)
    }
}

/// The `DomainCreate` guard: `creator` may create, and `target` is currently `Dead`.
pub open spec fn create_guard(s: Sys, creator: Dom, target: Dom) -> bool {
    s.maycreate.contains(creator) && !s.live.contains(target)
}

/// The transition function — `dispatch(caller, α)`. `DomainCreate` sets `life[target]` when its
/// guard holds; a fresh domain gains no other observable resource (and no creation authority of
/// its own — `maycreate` is unchanged).
pub open spec fn step(s: Sys, t: Trans) -> Sys {
    match t {
        Trans::Create { creator, target } => {
            if create_guard(s, creator, target) {
                Sys { live: s.live.insert(target), ..s }
            } else {
                s
            }
        },
        Trans::Send { sender, port } => {
            Sys { pending: s.pending.insert(send_target(s, sender, port)), ..s }
        },
        Trans::GrantMap { mapper, g } => {
            if grant_map_guard(s, mapper, g) {
                let f = s.grants[g].frame;
                let rec = s.grants[g];
                Sys {
                    refs: s.refs.insert(f, s.refs[f] + 1),
                    grants: s.grants.insert(g, GrantRec { count: rec.count + 1, ..rec }),
                    ..s
                }
            } else {
                s
            }
        },
        Trans::SetAffinity { caller, vcpu, aff } => {
            if set_affinity_guard(s, caller, vcpu) {
                Sys { vaff: s.vaff.insert(vcpu, aff), ..s }
            } else {
                s
            }
        },
    }
}

// ============================================================================================
// The observation `obs(a)` and the authorized-channel relation `interferes`.
// ============================================================================================

/// Domain `a`'s observation — its isolation surface, projected from `Sys`. Grows one field per
/// class. **`maycreate` is `a`'s OWN creation authority** — the GAP-C `obs`-refinement (module
/// docs): without it `step_consistent()` is false for the creation channel.
pub struct Obs {
    /// `life[a]`.
    pub live: bool,
    /// `may_create[a]` — `a`'s own creation authority (forced into `obs` by `step_consistent`).
    pub maycreate: bool,
    /// `a`'s **event-channel port links** — the interdomain-link map restricted to `a`'s ports
    /// (`a`'s port *state*). Moved by bind/close/destroy, not by a foreign `send`.
    pub peer: Map<Coord, Coord>,
    /// `a`'s **pending** bits — the pending set restricted to `a`'s ports. A foreign `send` with
    /// no signal channel to `a` cannot move these (`unwinding_signal.rs`).
    pub pend: Set<Coord>,
    /// `a`'s **grant rows** (as grantor), incl. live-map counts.
    pub grows: Map<int, GrantRec>,
    /// `a`'s **owned-frame reference counts**.
    pub frefs: Map<int, nat>,
    /// `a`'s **read-closure** (`obs⁺`) — read-caps for grants naming `a` as grantee. The
    /// confidentiality read direction (`read_closure.rs`).
    pub read_caps: Map<int, ReadCap>,
    /// `a`'s **vCPU affinities**.
    pub aff: Map<int, nat>,
    /// `a`'s **incoming control edges** — who controls `a` (self-authority; GAP-C).
    pub controllers: Set<(Dom, Dom)>,
}

/// `obs(s, a)` — the projection of `s` onto what belongs to `a`.
pub open spec fn obs(s: Sys, a: Dom) -> Obs {
    Obs {
        live: s.live.contains(a),
        maycreate: s.maycreate.contains(a),
        peer: s.peer.filter_keys(owned_by(a)),
        pend: s.pending.filter(owned_by(a)),
        grows: a_grant_rows(s, a),
        frefs: a_frame_refs(s, a),
        read_caps: a_read_caps(s, a),
        aff: a_affinity(s, a),
        controllers: a_controllers(s, a),
    }
}

/// `a` holds a port toward `b`: some interdomain port owned by `a` whose peer lies in domain `b`
/// (the signal channel's `a`-side term — `noninterference.rs::a_port_toward`,
/// `unwinding_signal.rs::holds_port_toward`).
pub open spec fn a_holds_port_toward(s: Sys, a: Dom, b: Dom) -> bool {
    exists|p: int| #![trigger s.peer[(a, p)]]
        s.peer.dom().contains((a, p)) && (s.peer[(a, p)]).0 == b
}

/// `a`'s **grant rows** (as grantor) — the grant table restricted to entries `a` granted. A peer
/// mapping one of these moves this projection (`frame_lemma.rs`; `noninterference.rs::obs`).
pub open spec fn a_grant_rows(s: Sys, a: Dom) -> Map<int, GrantRec> {
    s.grants.filter_keys(|g: int| s.grants.dom().contains(g) && s.grants[g].grantor == a)
}

/// `a`'s **owned-frame reference counts** — `refs` restricted to frames `a` owns. The quantity a
/// peer's authorized `GrantMap` moves (`frame_lemma.rs`; `noninterference.rs::obs`).
pub open spec fn a_frame_refs(s: Sys, a: Dom) -> Map<int, nat> {
    s.refs.filter_keys(|f: int| s.owner.dom().contains(f) && s.owner[f] == a)
}

/// `a` has an active grant with grantee `b` — the **consent** channel's `a`-side term
/// (`noninterference.rs::a_grants_to`).
pub open spec fn a_grants_to(s: Sys, a: Dom, b: Dom) -> bool {
    exists|g: int| #![trigger s.grants[g]]
        s.grants.dom().contains(g) && s.grants[g].grantor == a && s.grants[g].grantee == b
            && s.grants[g].active
}

/// One entry of `a`'s **read-closure** (`obs⁺`, `read_closure.rs`): for a grant naming `a` as
/// grantee, the partner state `a`'s `GrantMap` *reads* — the grant's `grantor`, `frame`, whether
/// it is `active`, the current `owner` of the frame (the `StaleGrant` check), and `a`'s own
/// live-map `count`. Precisely what `a`'s cross-domain map/copy reads and writes.
pub struct ReadCap {
    pub grantor: Dom,
    pub frame: int,
    pub active: bool,
    pub owner: Dom,
    pub count: nat,
}

/// `a`'s **read-closure** — for every grant naming `a` as grantee, its `ReadCap`. `obs⁺(a)` is
/// `obs(a)` together with this (the `read_caps` field of `Obs`). The confidentiality read
/// direction: `a` observes, through a held grant, exactly the partner state that grant lets it
/// act on (`read_closure.rs`). The `owner` component is the one forced by `step_consistent` — a
/// map's success reads the grantor's frame ownership, so `obs⁺` must expose it (else Verus rejects
/// step consistency for `a`'s own map; the read-direction non-vacuity witness).
pub open spec fn a_read_caps(s: Sys, a: Dom) -> Map<int, ReadCap> {
    Map::new(
        s.grants.dom().filter(|g: int| s.grants[g].grantee == a),
        |g: int|
            ReadCap {
                grantor: s.grants[g].grantor,
                frame: s.grants[g].frame,
                active: s.grants[g].active,
                owner: s.owner[s.grants[g].frame],
                count: s.grants[g].count,
            },
    )
}

/// `b` controls what `a` **reads** — the confidentiality dual `⇝⁺` (`read_closure.rs`): `b` is the
/// grantor of a grant `a` holds (only the grantor can end/alter it), or `b` currently owns a frame
/// behind such a grant (only the owner can re-own it). `interferes := ⇝ ∪ ⇝⁺`.
pub open spec fn reads_from(s: Sys, a: Dom, b: Dom) -> bool {
    exists|g: int| #![trigger s.grants[g]]
        s.grants.dom().contains(g) && s.grants[g].grantee == a && (s.grants[g].grantor == b
            || s.owner[s.grants[g].frame] == b)
}

/// `a`'s **vCPU affinity** — the affinity map restricted to vCPUs `a` owns (`unwinding_control.rs`;
/// `noninterference.rs::obs`). What an authorized controller's `SchedSetAffinity` moves.
pub open spec fn a_affinity(s: Sys, a: Dom) -> Map<int, nat> {
    s.vaff.filter_keys(|v: int| s.vowner.dom().contains(v) && s.vowner[v] == a)
}

/// `a`'s **incoming controllers** — the control edges pointing at `a`. A domain observes *its own*
/// incoming authority (the GAP-C self-authority refinement, control analogue of `may_create[a]`):
/// without it, `step_consistent` fails for the affinity channel (the guard `controls[b][a]` would
/// be unobserved). `interferes` (control term) governs who may change it.
pub open spec fn a_controllers(s: Sys, a: Dom) -> Set<(Dom, Dom)> {
    s.controls.filter(|e: (Dom, Dom)| e.1 == a)
}

/// The authorized-channel relation `b ⇝ a`: a step by `b` may legitimately move `obs(a)` iff a
/// direct relationship holds. State-dependent and intransitive (design doc §2.2). Grows one
/// disjunct per class.
///
/// * **self** — `b == a`;
/// * **creation** — `may_create[b] ∧ ¬life[a]` (a `may_create` domain may lift a `Dead` slot);
/// * **signal** — `a` holds a port toward `b` (`b`'s send/close/bind moves `a`'s port state /
///   pending bit);
/// * **consent** — `a` has an active grant with grantee `b` (`b` may map it, moving `a`'s frame
///   refs and grant map-counts);
/// * **read (`⇝⁺`)** — `b` controls what `a` reads through a grant it holds (grantor / frame owner
///   — `read_closure.rs`), the confidentiality dual;
/// * **authority** — `b` controls `a` (may set `a`'s vCPU affinity, or destroy `a`).
pub open spec fn interferes(s: Sys, b: Dom, a: Dom) -> bool {
    ||| b == a
    ||| (s.maycreate.contains(b) && !s.live.contains(a))
    ||| a_holds_port_toward(s, a, b)
    ||| a_grants_to(s, a, b)
    ||| reads_from(s, a, b)
    ||| s.controls.contains((b, a))
}

// ============================================================================================
// Well-formedness — the reachable-state invariants (Tiers A–C) the per-transition local-respect
// lemmas hold UNDER. `local_respect`/`step_consistent` are stated relative to `wf`, and `wf` is
// proven PRESERVED by `step` (`wf_step`) so the trace induction carries it. Grows one conjunct
// per class that borrows a relational invariant (signal: reciprocity; grant: map-identity/
// misowned). The creation slice needs none, so `wf` starts as `true`.
// ============================================================================================

/// **Event-channel reciprocity** (`evtchn.rs::first_violation`, `ReciprocityBroken`): every
/// interdomain port's peer is itself an interdomain port pointing back — the link map is an
/// **involution** on its domain. The relational invariant the signal locality borrows from
/// (`unwinding_signal.rs`).
pub open spec fn involution(peer: Map<Coord, Coord>) -> bool {
    forall|k: Coord| #![trigger peer[k]]
        peer.dom().contains(k) ==> peer.dom().contains(peer[k]) && peer[peer[k]] == k
}

/// The conjunction of the reachable-state invariants the local-respect lemmas borrow from
/// (design doc §2.2 — the invariants keep the channel relation honest). Populated per class.
///
/// * `involution(peer)` — event-channel reciprocity (signal channel);
/// * `refs.dom() == owner.dom()` — every owned frame carries a reference count (so a frame owned
///   by `a` is always in `a`'s frame-refs projection; the memory channel / read-closure);
/// * every grant names an **owned** frame — so a held grant's `owner` read-cap is well-defined
///   (the read direction, `read_closure.rs`).
pub open spec fn wf(s: Sys) -> bool {
    &&& involution(s.peer)
    &&& s.refs.dom() == s.owner.dom()
    &&& forall|g: int| #![trigger s.grants[g]]
        s.grants.dom().contains(g) ==> s.owner.dom().contains(s.grants[g].frame)
    &&& s.vaff.dom() == s.vowner.dom()
}

/// **`wf` is preserved by every transition** — so the trace induction stays inside the reachable
/// subspace. (The Tiers A–C preservation results, here for the modeled transitions.) Trivial
/// while `wf` is `true`; each class that adds a conjunct discharges its preservation here.
pub proof fn wf_step(s: Sys, t: Trans)
    requires
        wf(s),
    ensures
        wf(step(s, t)),
{
    // No transition touches the interdomain-link map, so reciprocity is preserved outright.
    assert(step(s, t).peer == s.peer);
    // `refs.dom() == owner.dom()`: Create/Send touch neither; GrantMap re-inserts a frame that is
    // already owned (the guard reads its owner), so `refs.dom()` is unchanged and `owner` is not
    // written.
    match t {
        Trans::GrantMap { mapper, g } => {
            if grant_map_guard(s, mapper, g) {
                let f = s.grants[g].frame;
                assert(s.owner.dom().contains(f));  // guard's StaleGrant read
                assert(s.refs.dom().contains(f));   // wf: refs.dom() == owner.dom()
                assert(step(s, t).refs.dom() == s.refs.dom());
            }
        },
        _ => {},
    }
    assert(step(s, t).refs.dom() == step(s, t).owner.dom());
    // Grants name owned frames: no transition adds a grant or changes a grant's frame, and
    // GrantMap re-inserts the same grant id with the same frame (only `count` bumps), while
    // `owner`'s domain never shrinks.
    assert(step(s, t).owner.dom() == s.owner.dom());
    assert forall|gi: int| #![trigger step(s, t).grants[gi]]
        step(s, t).grants.dom().contains(gi) implies step(s, t).owner.dom().contains(
        step(s, t).grants[gi].frame,
    ) by {
        // step's grants differ from s.grants only at the GrantMap'd key, with the same frame;
        // owner's domain is unchanged, and s satisfies the invariant.
        assert(step(s, t).grants[gi].frame == s.grants[gi].frame);
        assert(step(s, t).grants.dom().contains(gi) ==> s.grants.dom().contains(gi));
    }
    // `vaff.dom() == vowner.dom()`: only SetAffinity touches `vaff`, re-inserting a vCPU already
    // owned (the guard reads its owner); `vowner` is never written.
    match t {
        Trans::SetAffinity { caller, vcpu, aff } => {
            if set_affinity_guard(s, caller, vcpu) {
                assert(s.vowner.dom().contains(vcpu));  // guard
                assert(step(s, t).vaff.dom() == s.vaff.dom());
            }
        },
        _ => {},
    }
    assert(step(s, t).vaff.dom() == step(s, t).vowner.dom());
}

// ============================================================================================
// The two unwinding conditions — stated exactly as in noninterference_theorem.rs, but here
// PROVEN for the concrete definitions above (not taken as premises).
// ============================================================================================

/// **Local respect** — a step by a principal with no authorized channel to `a` leaves `obs(a)`
/// unchanged. (The meta-theorem's premise; here a discharged theorem.)
pub open spec fn local_respect() -> bool {
    forall|s: Sys, t: Trans, a: Dom|
        wf(s) && actor(t) != a && !interferes(s, actor(t), a) ==> #[trigger] obs(step(s, t), a)
            == obs(s, a)
}

/// **Step consistency** — `obs(a)`'s successor is a function of `obs(a)` and the actor's
/// observation. (The meta-theorem's premise; here a discharged theorem.)
pub open spec fn step_consistent() -> bool {
    forall|s: Sys, u: Sys, t: Trans, a: Dom|
        #![trigger obs(step(s, t), a), obs(step(u, t), a)]
        wf(s) && wf(u) && obs(s, a) == obs(u, a) && obs(s, actor(t)) == obs(u, actor(t))
            ==> obs(step(s, t), a) == obs(step(u, t), a)
}

/// **Local respect holds for the concrete system** (∀-N). Case-split over the transition class;
/// each case is the corresponding per-transition fragment, here over the composite `obs`.
///
/// *Creation* (`unwinding_create.rs`): the step writes only `life[target]`, and only when its
/// guard fires. `maycreate` is never touched, so `obs(a).maycreate` is preserved outright. For
/// `obs(a).live`: if `target != a` it is untouched; if `target == a` the channel's absence
/// (`¬(may_create[creator] ∧ ¬life[a])`) makes the guard false, so `life[a]` does not move.
pub proof fn local_respect_holds()
    ensures
        local_respect(),
{
    assert forall|s: Sys, t: Trans, a: Dom|
        wf(s) && actor(t) != a && !interferes(s, actor(t), a) implies #[trigger] obs(step(s, t), a)
        == obs(s, a) by {
        match t {
            Trans::Create { creator, target } => {
                // ¬interferes(s, creator, a) with creator != a ⟹ ¬(may_create[creator] ∧ ¬life[a]),
                // i.e. the guard cannot fire for target == a. And maycreate/peer/pending are not
                // written by Create.
                assert(obs(step(s, t), a) == obs(s, a));
            },
            Trans::Send { sender, port } => {
                // The two-sides reciprocity bridge (`unwinding_signal.rs`): ¬interferes ⟹ `a`
                // holds no port toward `sender`; the involution lifts that to "`sender` holds no
                // port toward `a`", so the send target is not one of `a`'s ports.
                let tgt = send_target(s, sender, port);
                assert(tgt.0 != a) by {
                    if s.peer.dom().contains((sender, port)) {
                        // tgt = peer[(sender,port)]. If tgt.0 == a, the involution gives a reverse
                        // `a`-port toward `sender` at tgt — contradicting ¬a_holds_port_toward.
                        if tgt.0 == a {
                            assert(s.peer.dom().contains(tgt) && s.peer[tgt] == (sender, port));
                            assert(s.peer.dom().contains((a, tgt.1)) && (s.peer[(a, tgt.1)]).0
                                == sender);
                            assert(a_holds_port_toward(s, a, sender));
                        }
                    }
                    // else tgt == (sender, port), and sender != a.
                }
                // Send touches only `pending`, and only at `tgt` ∉ `a`'s coords, so `a`'s pending
                // restriction (and every other obs component) is unchanged.
                assert(obs(step(s, t), a).pend =~= obs(s, a).pend);
                assert(obs(step(s, t), a) == obs(s, a));
            },
            Trans::GrantMap { mapper, g } => {
                broadcast use vstd::set::group_set_lemmas, vstd::map::group_map_lemmas;
                if grant_map_guard(s, mapper, g) {
                    let rec = s.grants[g];
                    let f = rec.frame;
                    // The guard gives grantee == mapper (= actor b), active, owner[f] == grantor.
                    // If the modified grant's grantor were `a`, then `a` grants to `b` actively —
                    // the consent channel, contradicting ¬interferes. So grantor != a, hence the
                    // frame's owner != a: the map touches neither `a`'s grant rows nor `a`'s frame
                    // refs (guard-shaped locality, `frame_lemma.rs`).
                    assert(rec.grantor != a) by {
                        if rec.grantor == a {
                            assert(a_grants_to(s, a, mapper));  // witness g
                        }
                    }
                    assert(s.owner[f] == rec.grantor && rec.grantor != a);
                    assert(obs(step(s, t), a).grows =~= obs(s, a).grows);
                    assert(obs(step(s, t), a).frefs =~= obs(s, a).frefs);
                    // Read-closure: the mapped grant has grantee == mapper == b != a, so it is not
                    // one of `a`'s held grants; `a`'s read-caps (and the owners behind them) are
                    // untouched.
                    assert(rec.grantee == mapper && mapper != a);
                    assert(obs(step(s, t), a).read_caps =~= obs(s, a).read_caps);
                }
                assert(obs(step(s, t), a) == obs(s, a));
            },
            Trans::SetAffinity { caller, vcpu, aff } => {
                broadcast use vstd::set::group_set_lemmas, vstd::map::group_map_lemmas;
                if set_affinity_guard(s, caller, vcpu) {
                    // The written vCPU is not `a`'s: else the guard would need `caller == a`
                    // (excluded, `caller != a`) or `controls[caller][a]` (excluded by ¬interferes)
                    // — the write-restriction IS the authorization guard (design-lesson #9).
                    assert(s.vowner[vcpu] != a) by {
                        if s.vowner[vcpu] == a {
                            assert(s.controls.contains((caller, a)));
                        }
                    }
                    assert(obs(step(s, t), a).aff =~= obs(s, a).aff);
                }
                assert(obs(step(s, t), a) == obs(s, a));
            },
        }
    }
}

/// **Step consistency holds for the concrete system** (∀-N). The creation channel factors through
/// the read-closed `obs`: the successor `life[a]` depends only on `life[a]` (in `obs(a)`) and
/// `may_create[creator]` (in `obs(creator)` — the GAP-C refinement); `maycreate` is unchanged.
/// Two states agreeing on both observations compute the same successor `obs(a)`.
pub proof fn step_consistent_holds()
    ensures
        step_consistent(),
{
    assert forall|s: Sys, u: Sys, t: Trans, a: Dom|
        wf(s) && wf(u) && obs(s, a) == obs(u, a) && obs(s, actor(t)) == obs(u, actor(t)) implies
        #[trigger] obs(step(s, t), a) == #[trigger] obs(step(u, t), a) by {
        match t {
            Trans::Create { creator, target } => {
                // obs(·,a).live == live.contains(a); obs(·,creator).maycreate ==
                // maycreate.contains(creator). Both agree across s,u, so the guard (for target==a)
                // and the write agree; for target!=a, life[a] is untouched on both sides.
                assert(obs(step(s, t), a) == obs(step(u, t), a));
            },
            Trans::Send { sender, port } => {
                broadcast use vstd::set::group_set_lemmas, vstd::map::group_map_lemmas;
                // The send target is a function of `sender`'s port link — which lies in
                // `obs(sender).peer` (the sender-restricted link map), so it agrees across s,u.
                let k = (sender, port);
                assert(owned_by(sender)(k));  // k.0 == sender
                // filter_keys keeps `k` (it is owned by `sender`), with its value — so obs equality
                // at `sender` pins the domain-membership and value of the link at `k`.
                assert(obs(s, sender).peer.dom().contains(k) == s.peer.dom().contains(k));
                assert(obs(u, sender).peer.dom().contains(k) == u.peer.dom().contains(k));
                assert(s.peer.dom().contains(k) == u.peer.dom().contains(k));
                assert(s.peer.dom().contains(k) ==> obs(s, sender).peer[k] == s.peer[k]);
                assert(u.peer.dom().contains(k) ==> obs(u, sender).peer[k] == u.peer[k]);
                let tgt = send_target(s, sender, port);
                assert(send_target(u, sender, port) == tgt);
                assert(step(s, t).pending == s.pending.insert(tgt));
                assert(step(u, t).pending == u.pending.insert(tgt));
                // With the target equal and `a`'s base pending equal (from obs(s,a)==obs(u,a)),
                // the successor pending restrictions agree pointwise; the filter lemma + the
                // insert lemma discharge each element. peer/live/maycreate are untouched by Send.
                assert(obs(s, a).pend == obs(u, a).pend);
                assert forall|x: Coord| obs(step(s, t), a).pend.contains(x)
                    == obs(step(u, t), a).pend.contains(x) by {
                    assert(obs(s, a).pend.contains(x) == obs(u, a).pend.contains(x));
                }
                assert(obs(step(s, t), a).pend =~= obs(step(u, t), a).pend);
                assert(obs(step(s, t), a) == obs(step(u, t), a));
            },
            Trans::GrantMap { mapper, g } => {
                broadcast use vstd::set::group_set_lemmas, vstd::map::group_map_lemmas;
                // A GrantMap reaches `a`'s surface only via `a`'s OWN grant row `g` and the frame
                // it names, whose values lie in obs(a); so obs(step,a) is a function of obs(a)
                // alone (the actor's observation is not even needed). The row `g` touches `a` iff
                // it is one of `a`'s grant rows; obs(a)-agreement pins that, the row, and the
                // frame's owner (via `a`'s frame-refs), hence the guard and the increment.
                let touches = s.grants.dom().contains(g) && s.grants[g].grantor == a;
                assert(touches == (u.grants.dom().contains(g) && u.grants[g].grantor == a)) by {
                    assert(obs(s, a).grows.dom().contains(g) == touches);
                    assert(obs(u, a).grows.dom().contains(g) == (u.grants.dom().contains(g)
                        && u.grants[g].grantor == a));
                }
                if touches {
                    // The row `g` is one of `a`'s: obs(a)-agreement pins the record, and the
                    // frame's owner==a (guard's StaleGrant read) via `a`'s frame-refs — so the
                    // guard and the increment are identical across s,u.
                    assert(s.grants[g] == u.grants[g]) by {
                        assert(obs(s, a).grows[g] == s.grants[g]);
                        assert(obs(u, a).grows[g] == u.grants[g]);
                    }
                    let f = s.grants[g].frame;
                    assert(s.owner.dom().contains(f) && s.owner[f] == a
                        <==> obs(s, a).frefs.dom().contains(f));
                    assert(u.owner.dom().contains(f) && u.owner[f] == a
                        <==> obs(u, a).frefs.dom().contains(f));
                    assert(grant_map_guard(s, mapper, g) == grant_map_guard(u, mapper, g));
                    if grant_map_guard(s, mapper, g) {
                        // owner[f] == grantor == a, so f is in `a`'s frame-refs; its ref value
                        // agrees across s,u, so both get the same `+1`.
                        assert(obs(s, a).frefs.dom().contains(f) && obs(u, a).frefs.dom().contains(
                            f,
                        ));
                        assert(s.refs[f] == obs(s, a).frefs[f] && u.refs[f] == obs(u, a).frefs[f]);
                    }
                    // The successor grant maps differ from s/u only at key `g` (an in-place count
                    // bump) — and agree with EACH OTHER at `g` (same record, same guard). At every
                    // other key they equal `s.grants`/`u.grants`, whose `a`-projections obs-agree.
                    assert_maps_equal!(obs(step(s, t), a).grows, obs(step(u, t), a).grows, k => {
                        if k != g {
                            assert(step(s, t).grants[k] == s.grants[k]);
                            assert(step(u, t).grants[k] == u.grants[k]);
                            assert(obs(s, a).grows.dom().contains(k) == obs(u, a).grows.dom().contains(k));
                            if obs(s, a).grows.dom().contains(k) {
                                assert(obs(s, a).grows[k] == obs(u, a).grows[k]);
                            }
                        }
                    });
                    // Frame refs: same shape — the only frame touched is `f` (when the guard
                    // fires), whose ref value obs-agrees; every other frame is untouched.
                    assert_maps_equal!(obs(step(s, t), a).frefs, obs(step(u, t), a).frefs, fr => {
                        if fr != f || !grant_map_guard(s, mapper, g) {
                            assert(step(s, t).refs[fr] == s.refs[fr]);
                            assert(step(u, t).refs[fr] == u.refs[fr]);
                            assert(obs(s, a).frefs.dom().contains(fr) == obs(u, a).frefs.dom().contains(fr));
                            if obs(s, a).frefs.dom().contains(fr) {
                                assert(obs(s, a).frefs[fr] == obs(u, a).frefs[fr]);
                            }
                        }
                    });
                } else {
                    // `g` is not one of `a`'s grant rows: the map modifies a non-`a` grant row
                    // (grantor != a) and, if the guard fires, a frame owned by that non-`a`
                    // grantor — neither in `a`'s projection. So obs(a) is unchanged on each side
                    // (the local-respect argument), and the two are equal by obs(a)-agreement.
                    assert(obs(step(s, t), a).grows =~= obs(s, a).grows);
                    assert(obs(step(u, t), a).grows =~= obs(u, a).grows);
                    assert(obs(step(s, t), a).frefs =~= obs(s, a).frefs);
                    assert(obs(step(u, t), a).frefs =~= obs(u, a).frefs);
                }
                // ---- Read-closure (the confidentiality READ direction, `read_closure.rs`) ----
                // The map touches `a`'s read-caps iff its grantee is `a` (⟺ mapper == a). Then
                // obs(a).read_caps pins the record AND the frame's `owner` (the StaleGrant read) —
                // so the guard and the count-bump are identical across s,u. This is exactly why
                // `obs⁺` must carry `owner`: without it the guard is unobserved and Verus rejects.
                broadcast use vstd::map_lib::group_map_properties;
                let reads = s.grants.dom().contains(g) && s.grants[g].grantee == a;
                assert(reads == (u.grants.dom().contains(g) && u.grants[g].grantee == a)) by {
                    assert(obs(s, a).read_caps.dom().contains(g) == reads);
                    assert(obs(u, a).read_caps.dom().contains(g) == (u.grants.dom().contains(g)
                        && u.grants[g].grantee == a));
                }
                if reads {
                    assert(obs(s, a).read_caps[g] == obs(u, a).read_caps[g]);
                    let fr = s.grants[g].frame;
                    // Record + frame owner pinned by the read-cap (the `owner` component).
                    assert(s.grants[g].grantor == u.grants[g].grantor && fr == u.grants[g].frame
                        && s.grants[g].active == u.grants[g].active && s.grants[g].count
                        == u.grants[g].count && s.owner[fr] == u.owner[fr]);
                    assert(s.owner.dom().contains(fr) && u.owner.dom().contains(fr));  // wf
                    assert(grant_map_guard(s, mapper, g) == grant_map_guard(u, mapper, g));
                }
                assert_maps_equal!(obs(step(s, t), a).read_caps, obs(step(u, t), a).read_caps, k => {
                    if k != g {
                        assert(step(s, t).grants[k] == s.grants[k]);
                        assert(step(u, t).grants[k] == u.grants[k]);
                        assert(obs(s, a).read_caps.dom().contains(k) == obs(u, a).read_caps.dom().contains(k));
                        if obs(s, a).read_caps.dom().contains(k) {
                            assert(obs(s, a).read_caps[k] == obs(u, a).read_caps[k]);
                        }
                    }
                });
                assert(obs(step(s, t), a) == obs(step(u, t), a));
            },
            Trans::SetAffinity { caller, vcpu, aff } => {
                broadcast use vstd::set::group_set_lemmas, vstd::map::group_map_lemmas;
                // The affinity write reaches `a` iff the vCPU is `a`'s (⟺ vcpu ∈ obs(a).aff, given
                // vaff.dom == vowner.dom). obs(a) pins that AND the guard: `caller == a` or
                // `controls[caller][a]` (in `a`'s observed incoming controllers). So the guard and
                // the write agree across s,u.
                let affects = s.vowner.dom().contains(vcpu) && s.vowner[vcpu] == a;
                assert(affects == (u.vowner.dom().contains(vcpu) && u.vowner[vcpu] == a)) by {
                    assert(obs(s, a).aff.dom().contains(vcpu) == affects);
                    assert(obs(u, a).aff.dom().contains(vcpu) == (u.vowner.dom().contains(vcpu)
                        && u.vowner[vcpu] == a));
                }
                if affects {
                    assert(s.controls.contains((caller, a)) == u.controls.contains((caller, a))) by {
                        assert(obs(s, a).controllers.contains((caller, a)) == s.controls.contains(
                            (caller, a),
                        ));
                        assert(obs(u, a).controllers.contains((caller, a)) == u.controls.contains(
                            (caller, a),
                        ));
                    }
                    assert(set_affinity_guard(s, caller, vcpu) == set_affinity_guard(u, caller, vcpu));
                }
                assert_maps_equal!(obs(step(s, t), a).aff, obs(step(u, t), a).aff, v => {
                    if v != vcpu {
                        assert(step(s, t).vaff[v] == s.vaff[v]);
                        assert(step(u, t).vaff[v] == u.vaff[v]);
                        assert(obs(s, a).aff.dom().contains(v) == obs(u, a).aff.dom().contains(v));
                        if obs(s, a).aff.dom().contains(v) {
                            assert(obs(s, a).aff[v] == obs(u, a).aff[v]);
                        }
                    }
                });
                assert(obs(step(s, t), a) == obs(step(u, t), a));
            },
        }
    }
}

// ============================================================================================
// The whole-run assembly — the generic unwinding induction (noninterference_theorem.rs),
// re-run over the concrete definitions with the two conditions DISCHARGED, not assumed.
// ============================================================================================

/// Fold a trace of actions over a state — one execution.
pub open spec fn run(s: Sys, tr: Seq<Trans>) -> Sys
    decreases tr.len(),
{
    if tr.len() == 0 {
        s
    } else {
        run(step(s, tr[0]), tr.subrange(1, tr.len() as int))
    }
}

/// Every action in `tr`, at the point it is applied, is by a principal that does not interfere
/// with `a` (and is not `a`) — an execution of activity entirely unrelated to `a`.
pub open spec fn trace_noninterfering(s: Sys, tr: Seq<Trans>, a: Dom) -> bool
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

/// Two executions agree, at each step, on the acting domain's observation.
pub open spec fn traces_agree_on_actor(s: Sys, u: Sys, tr: Seq<Trans>, a: Dom) -> bool
    decreases tr.len(),
{
    if tr.len() == 0 {
        true
    } else {
        obs(s, actor(tr[0])) == obs(u, actor(tr[0])) && traces_agree_on_actor(
            step(s, tr[0]),
            step(u, tr[0]),
            tr.subrange(1, tr.len() as int),
            a,
        )
    }
}

/// **Theorem A (integrity), premise-free.** A domain `a` sees a constant observation across any
/// execution of principals that do not interfere with it. Unlike `noninterference_theorem.rs`,
/// this takes **no** `local_respect()` premise — it invokes the discharged `local_respect_holds`.
pub proof fn ni_theorem_a(s: Sys, tr: Seq<Trans>, a: Dom)
    requires
        wf(s),
        trace_noninterfering(s, tr, a),
    ensures
        obs(run(s, tr), a) == obs(s, a),
    decreases tr.len(),
{
    local_respect_holds();
    if tr.len() > 0 {
        let act = tr[0];
        let s1 = step(s, act);
        assert(obs(s1, a) == obs(s, a));
        wf_step(s, act);
        ni_theorem_a(s1, tr.subrange(1, tr.len() as int), a);
    }
}

/// **Theorem B (confidentiality), premise-free.** Two executions that start `obs(a)`-equivalent
/// and agree at each step on the acting domain's observation stay `obs(a)`-equivalent throughout.
/// Takes **no** `step_consistent()` premise — it invokes the discharged `step_consistent_holds`.
pub proof fn ni_theorem_b(s: Sys, u: Sys, tr: Seq<Trans>, a: Dom)
    requires
        wf(s),
        wf(u),
        obs(s, a) == obs(u, a),
        traces_agree_on_actor(s, u, tr, a),
    ensures
        obs(run(s, tr), a) == obs(run(u, tr), a),
    decreases tr.len(),
{
    step_consistent_holds();
    if tr.len() > 0 {
        let act = tr[0];
        assert(obs(step(s, act), a) == obs(step(u, act), a));
        wf_step(s, act);
        wf_step(u, act);
        ni_theorem_b(step(s, act), step(u, act), tr.subrange(1, tr.len() as int), a);
    }
}

} // verus!
