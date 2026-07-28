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
//! ## Scope of this file (all FIVE transition classes — GAP-C fully closed)
//!
//! `Trans` models **all five** Tier-D transition classes: `Create` (creation), `Send` (signal),
//! `GrantMap` (consent + the confidentiality read-closure), `SetAffinity` (authority), and
//! `Destroy` — the **`DomainDestroy` cascade**, the sole genuinely multi-domain transition
//! (`unwinding_destroy.rs`). Both unwinding conditions are discharged, and both trace theorems
//! (`ni_theorem_a`, `ni_theorem_b`) are premise-free, for all five.
//!
//! The cascade touches four `obs` components at once — `a`'s **ports** (`close_all`/
//! `clear_unbound_into` drop links naming `c`), **grant rows** (`revoke_grants_to` clears active
//! grants to `c`, and `c`'s own outgoing rows drop — the read direction), the **frame-map
//! population** (`drain_maps_of` releases `c`'s maps), and the **read-caps** (destroying `a`'s
//! grantor `c` alters `obs⁺(a)`) — and carries the intransitive **teardown-reach** term
//! (`interferes` gains `teardown_reach`: `∃c. controls[caller][c] ∧ reach(a, c)`, where `reach`
//! includes the read direction the pre-`obs⁺` §2.4 lacked — finding #3). The `map`-identity
//! (`unwinding_destroy.rs::no_c_map_over_a_frame`) is threaded as a `wf` invariant and proven
//! preserved (`wf_step_destroy`) so the drain is owner-local. Two modeling choices, recorded below.
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
//! ## Two findings the `DomainDestroy` proof forced
//!
//! * **The actor observes its own *outgoing* destroy authority.** `destroy_guard` reads
//!   `controls[caller][c]` — `caller`'s power over the *target* `c`, not over `a`. That edge is in
//!   neither `obs(a)` nor `obs(caller)` under the §2.1 (incoming-only) authority. So two runs
//!   agreeing on the documented observations can disagree on whether the destroy fires, and
//!   `step_consistent` is *false*. The fix (the outgoing analogue of the finding above): `obs(a)`
//!   carries `controls[a][·]` (`controls_out`), so the actor observes its own destroy authority.
//! * **The drain modelled `DomainBusy` away — and ②′-(c) then made the code agree.** When this
//!   file was written, `hypervisor::domain_destroy` *refused* teardown (`DomainBusy`) while a
//!   foreign domain mapped `c`'s frames — a `c`-frames property invisible to `a`/`caller`, which
//!   would break `step_consistent` outright. This carrier instead had the drain *clean up* those
//!   maps (`drain_pred` drops maps that are `c`'s **or** over a `c`-owned frame), justified as a
//!   sound over-approximation: the two coincide on `obs(a)` for `a ≠ c` — a map over `c`'s frame is
//!   never one of `a`'s — so the whole-run NI conclusion was unaffected and the guard stayed a
//!   function of the actor's `obs`. (It also keeps the `map`-identity trivially preserved: no
//!   survivor is over a `c`-owned frame, so its witness grant escapes the revoke.)
//!
//!   **This is no longer an over-approximation.** ②′-(c) replaced refuse-if-busy with
//!   force-reclaim (`grant::drain_foreign_maps_of` + `p2m::unlink_all_into`), for exactly the
//!   reason this carrier had to abstract it away — the refusal was an unobservable-state channel
//!   (and a DoS besides). The code now *is* the drain this carrier models, so the correspondence
//!   is exact rather than sound-but-loose. The modelling choice made here to keep the proof
//!   honest turned out to be the right semantics; the real-code bridge
//!   (`hv-sim::noninterference`) pins the resulting channel closure directly.
//!
//! Run: `verus --crate-type=lib hv-verify/verus/noninterference_instantiation.rs` (exit 0 = all
//! proven).

use vstd::prelude::*;
use vstd::assert_maps_equal;

verus! {

// ============================================================================================
// Seq-filter plumbing for the frame-map population (the frame-refs drain, `DomainDestroy`).
// ============================================================================================

/// `filter` is congruent under predicates that agree on the sequence's own elements — so a
/// pointwise-equal predicate substitution preserves the filtered result.
pub proof fn filter_ext<A>(sq: Seq<A>, p: spec_fn(A) -> bool, q: spec_fn(A) -> bool)
    requires
        forall|i: int| #![trigger sq[i]] 0 <= i < sq.len() ==> p(sq[i]) == q(sq[i]),
    ensures
        sq.filter(p) == sq.filter(q),
    decreases sq.len(),
{
    reveal(Seq::filter);
    if sq.len() > 0 {
        assert forall|i: int| #![trigger sq.drop_last()[i]] 0 <= i < sq.drop_last().len() implies p(
            sq.drop_last()[i],
        ) == q(sq.drop_last()[i]) by {
            assert(sq.drop_last()[i] == sq[i]);
        }
        filter_ext(sq.drop_last(), p, q);
    }
}

/// Filtering by `p` then `q` equals filtering by `p ∧ q` — filter composition (so filters
/// commute, and a drain restricted to a projection is the projection of the drain).
pub proof fn filter_and<A>(sq: Seq<A>, p: spec_fn(A) -> bool, q: spec_fn(A) -> bool)
    ensures
        sq.filter(p).filter(q) == sq.filter(|x: A| p(x) && q(x)),
    decreases sq.len(),
{
    reveal(Seq::filter);
    broadcast use Seq::lemma_filter_push;
    if sq.len() > 0 {
        filter_and(sq.drop_last(), p, q);
        assert(sq.drop_last().push(sq.last()) =~= sq);
        let last = sq.last();
        if p(last) {
            assert(sq.filter(p) == sq.drop_last().filter(p).push(last));
        }
    }
}

/// Filtering by an always-false predicate yields the empty sequence.
pub proof fn filter_false<A>(sq: Seq<A>)
    ensures
        sq.filter(|x: A| false) == Seq::<A>::empty(),
    decreases sq.len(),
{
    reveal(Seq::filter);
    if sq.len() > 0 {
        filter_false(sq.drop_last());
    }
}

/// **The compound drain is a no-op on `a`'s frames when `c` maps none of them** (`a ≠ c`). The
/// destroy filter drops `c`'s maps *and* maps over `c`-owned frames; on `a`'s frames (owned by
/// `a ≠ c`) the second clause is vacuous, so if no live map is *both* `c`'s and over an `a`-owned
/// frame, `a`'s frame-map population is unchanged (`unwinding_destroy.rs::drain_preserves_frame_refs`
/// at the population granularity).
pub proof fn compound_drain_preserves(maps: Seq<(Dom, int)>, owner: Map<int, Dom>, a: Dom, c: Dom)
    requires
        a != c,
        forall|i: int| #![trigger maps[i]]
            0 <= i < maps.len() ==> !(maps[i].0 == c && owner.dom().contains(maps[i].1)
                && owner[maps[i].1] == a),
    ensures
        maps.filter(drain_pred(owner, c)).filter(a_frame_pred(owner, a)) == maps.filter(
            a_frame_pred(owner, a),
        ),
{
    filter_and(maps, drain_pred(owner, c), a_frame_pred(owner, a));
    filter_ext(
        maps,
        |m: (Dom, int)| (drain_pred(owner, c))(m) && (a_frame_pred(owner, a))(m),
        a_frame_pred(owner, a),
    );
}

/// **`a`'s post-destroy frame maps as a function of `obs(a)`** (used by step consistency). When
/// `a ≠ c` the compound drain restricted to `a`'s frames is exactly `obs(a).frame_maps` with `c`'s
/// dropped; when `a == c` (`a` destroys itself) every `a`-frame map is over a `c`-owned frame, so
/// the population empties. Either way the result is determined by `obs(a).frame_maps`.
pub proof fn frame_maps_destroyed(maps: Seq<(Dom, int)>, owner: Map<int, Dom>, a: Dom, c: Dom)
    ensures
        maps.filter(drain_pred(owner, c)).filter(a_frame_pred(owner, a)) == (if a != c {
            maps.filter(a_frame_pred(owner, a)).filter(not_c_pred(c))
        } else {
            Seq::<(Dom, int)>::empty()
        }),
{
    filter_and(maps, drain_pred(owner, c), a_frame_pred(owner, a));
    if a != c {
        filter_and(maps, a_frame_pred(owner, a), not_c_pred(c));
        filter_ext(
            maps,
            |m: (Dom, int)| (drain_pred(owner, c))(m) && (a_frame_pred(owner, a))(m),
            |m: (Dom, int)| (a_frame_pred(owner, a))(m) && (not_c_pred(c))(m),
        );
    } else {
        filter_ext(
            maps,
            |m: (Dom, int)| (drain_pred(owner, c))(m) && (a_frame_pred(owner, a))(m),
            |m: (Dom, int)| false,
        );
        filter_false(maps);
    }
}

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
    /// The **live grant-map population** — one `(mapper, frame)` entry per live grant map
    /// (`grant::map` appends; `drain_maps_of(c)` filters out `c`'s). The per-frame *count*
    /// `|{ maps naming f }|` is `f`'s reference load (`p2m::refs`); modeled here as the
    /// population itself (the granularity `unwinding_destroy.rs`'s `Maps` uses), so the
    /// `DomainDestroy` drain is a `filter` and a peer's authorized `GrantMap` is a `push`.
    pub maps: Seq<(Dom, int)>,
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
    /// `DomainDestroy` — `caller` tears down `target` (guarded by `caller == target` or
    /// `controls[caller][target]` — and by nothing else: since ②′-(c) the code force-reclaims
    /// foreign holds on `target`'s frames rather than refusing over them, which is what this
    /// carrier already modelled). The sole
    /// **multi-domain** transition: the cascade reaches `target`'s *partners* — `close_all`/
    /// `clear_unbound_into` return/free ports naming `target`; `revoke_grants_to` clears active
    /// grants *to* `target` and `target`'s own outgoing grant rows drop (the read direction);
    /// `drain_maps_of` releases `target`'s maps, dropping the referenced frames' load. So a step by
    /// `caller` can move a *third* domain's `obs` — the intransitive **teardown-reach** channel
    /// (`unwinding_destroy.rs`).
    Destroy { caller: Dom, target: Dom },
}

/// The acting principal of an action — the `caller` of the `HvCall`.
pub open spec fn actor(t: Trans) -> Dom {
    match t {
        Trans::Create { creator, .. } => creator,
        Trans::Send { sender, .. } => sender,
        Trans::GrantMap { mapper, .. } => mapper,
        Trans::SetAffinity { caller, .. } => caller,
        Trans::Destroy { caller, .. } => caller,
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

/// The `DomainDestroy` guard: `caller` is authorized to destroy `target` — itself, or a domain it
/// controls (the write-restriction *is* the authorization, design-lesson #9). The authorization
/// reads `caller`'s **own outgoing** control edge `controls[caller][target]`, exposed by
/// `obs(caller).controls_out` — the actor observes its own destroy authority (the outgoing analogue
/// of the finding-#1 self-authority; without it `step_consistent` is false — the destroy fires in
/// one run and not the other while both agree on the documented `obs`).
pub open spec fn destroy_guard(s: Sys, caller: Dom, target: Dom) -> bool {
    caller == target || s.controls.contains((caller, target))
}

/// `a` has an **outbound reach relationship** with `c` — a reference *`a` holds naming `c`* that
/// the destroy of `c` would clear: `a` holds a port toward `c` (signal cleanup), or `a` granted
/// actively to `c` (consent revoke + frame drain). The per-target content of the
/// `noninterference::teardown_reach` term.
///
/// **The read direction is no longer here (⑦).** It used to carry `reads_from(s, a, c)` because
/// the read-closure sat on the integrity surface; now that `obs` is the narrow surface and the
/// read-closure lives on [`ObsPlus`], losing a read-cap is a *confidentiality* event, governed by
/// `step_consistent` — which needs no channel relation at all. What survives on the integrity side
/// is the **borrow** direction ([`borrows_from`]): the destroy drains `a`'s live *maps* over `c`'s
/// frames, and `a`'s `frame_maps` are in `obs`.
pub open spec fn reach(s: Sys, a: Dom, c: Dom) -> bool {
    a_holds_port_toward(s, a, c) || a_grants_to(s, a, c)
}

/// `a` **borrows from** `c` — `a` holds a live grant map over a frame `c` owns. This is precisely
/// what `c`'s teardown force-reclaims (its `drain_pred` drops every map over a `c`-owned frame), so
/// it is a write to `a`'s `frame_maps`, which `obs(a)` carries.
///
/// The mirror of `hv-sim::noninterference::a_borrows_from` (⑦). That bridge predicate also counts a
/// page-table edge of `a`'s rooted at a `c`-owned frame; this model has no page tables, a declared
/// modelling boundary (`docs/TIER-D-NONINTERFERENCE.md` §4a) — the grant-map half is the whole of
/// the borrow relation *here*.
pub open spec fn borrows_from(s: Sys, a: Dom, c: Dom) -> bool {
    exists|i: int| #![trigger s.maps[i]]
        0 <= i < s.maps.len() && (s.maps[i]).0 == a && s.owner[(s.maps[i]).1] == c
}

/// The **teardown-reach** channel — the intransitive two-hop: `caller` controls some `c` that `a`
/// reaches. `caller` destroying that `c` cleans up `a`'s outbound reference to it, moving `obs(a)`
/// (`docs/TIER-D-NONINTERFERENCE.md` §2.4; `unwinding_destroy.rs`).
pub open spec fn teardown_reach(s: Sys, b: Dom, a: Dom) -> bool {
    exists|c: Dom| #![trigger s.controls.contains((b, c))] s.controls.contains((b, c)) && reach(s, a, c)
}

/// The **teardown-borrow** channel — the *inbound* half of the two-hop, and the term that replaces
/// the old blanket `reads_from(s, a, b)` disjunct of [`interferes`] (⑦). `b` destroying a `c` that
/// `a` borrows from force-reclaims the page `a` was mapping, which `a` observes.
///
/// **The quantifier includes `c == b` — the self-destroy case — and it is load-bearing**, exactly as
/// in the bridge (`Channels::teardown_borrow_from`, design-lesson #61d). [`teardown_reach`] can omit
/// it because when `b` tears *itself* down, `a`'s outbound reference to `b` is a port `a` opened
/// toward `b` or a grant `a` offered `b` — already named by the *direct* signal and consent
/// disjuncts. The borrow direction has no such direct term: `a` borrowing from `b` means **`b`
/// granted to `a`**, the opposite of `a_grants_to(s, a, b)`. Self-authority is inherent rather than
/// an edge (`controls` never contains `(b, b)`), so it has to be spelled out — and dropping it is
/// precisely what makes `local_respect_holds` fail on the destroy case.
pub open spec fn teardown_borrow(s: Sys, b: Dom, a: Dom) -> bool {
    exists|c: Dom| #![trigger borrows_from(s, a, c)]
        (c == b || s.controls.contains((b, c))) && borrows_from(s, a, c)
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
                    maps: s.maps.push((mapper, f)),
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
        Trans::Destroy { caller, target } => {
            if destroy_guard(s, caller, target) {
                let c = target;
                Sys {
                    // ports: `close_all(c)` returns `c`'s interdomain peers, `clear_unbound_into(c)`
                    // frees `c`'s ports — modeled as dropping every link naming `c` (as a key, i.e.
                    // `c`'s own port, or as a value, i.e. a peer's port toward `c`). Involution-safe.
                    peer: s.peer.filter_keys(|k: Coord| k.0 != c && s.peer[k].0 != c),
                    // grant rows: `revoke_grants_to(c)` clears active grants *to* `c`, and `c`'s own
                    // outgoing rows drop with `c` — modeled as dropping every grant with grantor `c`
                    // or an active grantee `c`.
                    grants: s.grants.filter_keys(
                        |g: int|
                            !(s.grants[g].grantor == c || (s.grants[g].active
                                && s.grants[g].grantee == c)),
                    ),
                    // frame references: `drain_maps_of(c)` releases every map by `c`, and `c`'s own
                    // frames (freed with `c`) shed their maps too — so a surviving map is neither
                    // `c`'s nor over a `c`-owned frame. (This is `drain_foreign_maps_of` — what
                    // `DomainBusy` used to refuse over, and what ②′-(c) made the code actually do.
                    // It keeps the guard a function of the actor's `obs`; the drain is invisible to
                    // `obs(a)` for `a ≠ c`, since a map over `c`'s frame is not one of `a`'s.)
                    maps: s.maps.filter(drain_pred(s.owner, c)),
                    ..s
                }
            } else {
                s
            }
        },
    }
}

// ============================================================================================
// The observation `obs(a)` and the authorized-channel relation `interferes`.
// ============================================================================================

/// Domain `a`'s **integrity** observation — its isolation surface, projected from `Sys`. Grows one
/// field per class. **`maycreate` is `a`'s OWN creation authority** — the GAP-C `obs`-refinement
/// (module docs): without it `step_consistent()` is false for the creation channel.
///
/// **This is the narrow surface (⑦).** It deliberately carries no read-closure: see [`ObsPlus`].
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
    /// `a`'s **owned frames** — the set of machine frames `a` owns. No modeled transition re-owns
    /// a frame, so this is a stable observable; it exposes `owner[f] == a` (which `frame_maps`
    /// alone does not, for an as-yet-unmapped owned frame) — load-bearing for the memory channel's
    /// guard, `owner[frame] == grantor`.
    pub owned: Set<int>,
    /// `a`'s **frame-map population** — the live grant-map population restricted to `a`-owned
    /// frames (per-frame count = `a`'s owned-frame reference load). A peer's authorized
    /// `GrantMap` of `a`'s grant appends here; a `DomainDestroy` cascade drains it.
    pub frame_maps: Seq<(Dom, int)>,
    /// `a`'s **vCPU affinities**.
    pub aff: Map<int, nat>,
    /// `a`'s **incoming control edges** — who controls `a` (self-authority; GAP-C).
    pub controllers: Set<(Dom, Dom)>,
    /// `a`'s **outgoing control edges** — whom `a` controls (may set affinity on, or *destroy*).
    /// The actor observes its own destroy authority — without it `step_consistent` is false for the
    /// `DomainDestroy` channel (the outgoing analogue of the finding-#1 self-authority).
    pub controls_out: Set<(Dom, Dom)>,
}

/// `obs(s, a)` — the projection of `s` onto what belongs to `a`.
pub open spec fn obs(s: Sys, a: Dom) -> Obs {
    Obs {
        live: s.live.contains(a),
        maycreate: s.maycreate.contains(a),
        peer: s.peer.filter_keys(owned_by(a)),
        pend: s.pending.filter(owned_by(a)),
        grows: a_grant_rows(s, a),
        owned: a_owned_frames(s, a),
        frame_maps: a_frame_maps(s, a),
        aff: a_affinity(s, a),
        controllers: a_controllers(s, a),
        controls_out: a_controls_out(s, a),
    }
}

/// Domain `a`'s **confidentiality** observation, `obs⁺` — [`Obs`] extended with the read-closure.
///
/// **The two surfaces are different, and that is the point (⑦; design-lesson #58).** Integrity
/// (`local_respect`) asks what an unauthorized principal can *do to* `a`; confidentiality
/// (`step_consistent`) asks what `a` can *learn*. A grantor freely **creating** an offer to `a`
/// moves `a`'s read-caps — and that is not integrity interference, because a domain cannot stop
/// others revealing themselves to it. Carrying the read-closure on the integrity surface therefore
/// forced [`interferes`] to name a *blanket* read term (`reads_from(a, b)`: any grantor of `a`
/// interferes with `a` for **every** transition), which made Theorem A strictly weaker than it
/// needed to be — weaker, in particular, than what the real-code bridge
/// (`hv-sim::noninterference`) had been demonstrating with its own two-surface split all along.
/// Splitting here removes that term and closes the bridge↔composition divergence.
pub struct ObsPlus {
    /// The integrity surface, carried entire — `obs⁺ ⊇ obs`.
    pub base: Obs,
    /// `a`'s **read-closure** — read-caps for grants naming `a` as grantee. The confidentiality
    /// read direction (`read_closure.rs`), and the sole thing `obs⁺` adds.
    pub read_caps: Map<int, ReadCap>,
}

/// `obs⁺(s, a)` — the confidentiality projection: [`obs`] plus the read-closure.
pub open spec fn obs_plus(s: Sys, a: Dom) -> ObsPlus {
    ObsPlus { base: obs(s, a), read_caps: a_read_caps(s, a) }
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

/// `a`'s **owned frames** — the set of frames `owner` maps to `a`. Stable (no transition
/// re-owns a frame); exposes `owner[f] == a` for the memory-channel guard.
pub open spec fn a_owned_frames(s: Sys, a: Dom) -> Set<int> {
    s.owner.dom().filter(|f: int| s.owner[f] == a)
}

/// The "`(mapper, frame)` names a frame owned by `a`" predicate — projects the global map
/// population onto `a`'s owned frames.
pub open spec fn a_frame_pred(owner: Map<int, Dom>, a: Dom) -> spec_fn((Dom, int)) -> bool {
    |m: (Dom, int)| owner.dom().contains(m.1) && owner[m.1] == a
}

/// The `DomainDestroy` **map drain** predicate — a map survives iff it is not `c`'s and not over a
/// `c`-owned frame. (A named closure so every `filter` over it — in `step` and in the drain lemmas
/// — refers to the *same* spec object, which is how Verus matches filtered sequences.)
pub open spec fn drain_pred(owner: Map<int, Dom>, c: Dom) -> spec_fn((Dom, int)) -> bool {
    |m: (Dom, int)| m.0 != c && owner[m.1] != c
}

/// The "map is not `c`'s" predicate — `obs(a)`'s frame maps with `c`'s dropped (step consistency).
pub open spec fn not_c_pred(c: Dom) -> spec_fn((Dom, int)) -> bool {
    |m: (Dom, int)| m.0 != c
}

/// `a`'s **frame-map population** — the live map population restricted to frames `a` owns. Its
/// per-frame count is `a`'s owned-frame reference load; the quantity a peer's authorized
/// `GrantMap` appends to and a `DomainDestroy` drains (`frame_lemma.rs`, `unwinding_destroy.rs`;
/// `noninterference.rs::obs`).
pub open spec fn a_frame_maps(s: Sys, a: Dom) -> Seq<(Dom, int)> {
    s.maps.filter(a_frame_pred(s.owner, a))
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

/// `a`'s **outgoing control edges** — whom `a` controls. Exposes `controls[a][·]` so the actor
/// observes its own `DomainDestroy` authority (`destroy_guard`); without it `step_consistent` fails
/// for the destroy channel. Stable — no modeled transition writes the control matrix.
pub open spec fn a_controls_out(s: Sys, a: Dom) -> Set<(Dom, Dom)> {
    s.controls.filter(|e: (Dom, Dom)| e.0 == a)
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
/// * **authority** — `b` controls `a` (may set `a`'s vCPU affinity, or destroy `a`);
/// * **teardown-reach** — the intransitive outbound two-hop ([`teardown_reach`]);
/// * **teardown-borrow** — its inbound twin ([`teardown_borrow`]).
///
/// **⑦ removed a blanket `reads_from(s, a, b)` disjunct** that used to sit between *consent* and
/// *authority*. It authorized **any** grantor of `a` to move `obs(a)` via **any** transition — a
/// far wider licence than the flow it was there to name, which is the *self-destroy borrow*
/// ([`teardown_borrow`]'s `c == b` arm). It was unavoidable only while the read-closure sat on the
/// integrity surface; with the [`Obs`]/[`ObsPlus`] split it is not, and Theorem A is correspondingly
/// stronger — a grantor no longer interferes with its grantee merely by having offered.
/// The relation now has the same shape, term for term, as the real-code bridge's
/// `hv-sim::noninterference::Channels::authorized`.
pub open spec fn interferes(s: Sys, b: Dom, a: Dom) -> bool {
    ||| b == a
    ||| (s.maycreate.contains(b) && !s.live.contains(a))
    ||| a_holds_port_toward(s, a, b)
    ||| a_grants_to(s, a, b)
    ||| s.controls.contains((b, a))
    ||| teardown_reach(s, b, a)
    ||| teardown_borrow(s, b, a)
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

/// **The grant `map`-identity** (`grant.rs`; `unwinding_destroy.rs::no_c_map_over_a_frame`): every
/// live map `(mapper, frame)` is witnessed by an **active** grant whose grantor is the frame's
/// current owner, whose grantee is the mapper, and which names that frame. A map is created only
/// through `grant_map_guard` (which reads `owner[frame] == grantor`), stays active while mapped
/// (no-end-while-mapped), and no modeled transition re-owns a frame — so the map population never
/// outruns the grants that justify it. This is the relational invariant the `DomainDestroy` drain
/// borrows from: a map by `c` over an `a`-owned frame forces an active `a→c` grant.
pub open spec fn map_backed(s: Sys, i: int) -> bool {
    exists|g: int| #![trigger s.grants[g]]
        s.grants.dom().contains(g) && s.grants[g].active && s.grants[g].grantor == s.owner[s.maps[i].1]
            && s.grants[g].grantee == s.maps[i].0 && s.grants[g].frame == s.maps[i].1
}

/// Every live map is `map_backed`.
pub open spec fn map_identity(s: Sys) -> bool {
    forall|i: int| 0 <= i < s.maps.len() ==> #[trigger] map_backed(s, i)
}

/// The conjunction of the reachable-state invariants the local-respect lemmas borrow from
/// (design doc §2.2 — the invariants keep the channel relation honest). Populated per class.
///
/// * `involution(peer)` — event-channel reciprocity (signal channel);
/// * every grant names an **owned** frame — so a held grant's `owner` read-cap is well-defined
///   (the read direction, `read_closure.rs`);
/// * `vaff.dom() == vowner.dom()` — every vCPU carries an affinity (authority channel);
/// * `map_identity` — the grant `map`-identity (the `DomainDestroy` frame-refs drain).
pub open spec fn wf(s: Sys) -> bool {
    &&& involution(s.peer)
    &&& forall|g: int| #![trigger s.grants[g]]
        s.grants.dom().contains(g) ==> s.owner.dom().contains(s.grants[g].frame)
    &&& s.vaff.dom() == s.vowner.dom()
    &&& map_identity(s)
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
    if let Trans::Destroy { caller, target } = t {
        wf_step_destroy(s, caller, target);
        return ;
    }
    // No non-destroy transition touches the interdomain-link map, so reciprocity holds.
    assert(step(s, t).peer == s.peer);
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
    // `map_identity`: only GrantMap changes the map population (a `push`) or the grants (a count
    // bump at one key); Create/Send/SetAffinity touch none of `maps`/`grants`/`owner`, so the
    // witnesses carry over unchanged.
    assert forall|i: int| 0 <= i < step(s, t).maps.len() implies #[trigger] map_backed(
        step(s, t),
        i,
    ) by {
        {
            let st = step(s, t);
            let pushed = if let Trans::GrantMap { mapper, g } = t {
                grant_map_guard(s, mapper, g) && i == s.maps.len()
            } else {
                false
            };
            if pushed {
                // The pushed map `(mapper, f)`: witnessed by the mapped grant itself (active by the
                // guard, grantor == owner[f], grantee == mapper, frame == f).
                let (mapper, g) = if let Trans::GrantMap { mapper, g } = t {
                    (mapper, g)
                } else {
                    (0, 0)
                };
                let f = s.grants[g].frame;
                assert(st.maps[i] == (mapper, f));
                assert(st.grants.dom().contains(g) && st.grants[g].active && st.grants[g].grantor
                    == st.owner[st.maps[i].1] && st.grants[g].grantee == st.maps[i].0
                    && st.grants[g].frame == st.maps[i].1);
            } else {
                // Every other case leaves `maps[i]`, `owner`, and the *witnessing* fields of
                // `grants` fixed (GrantMap only bumps one grant's `count`; other transitions touch
                // no grant) — so `s`'s witness carries over.
                assert(st.maps[i] == s.maps[i] && st.owner == s.owner);
                assert(map_backed(s, i));  // wf
                let gw = choose|gw: int| #![trigger s.grants[gw]]
                    s.grants.dom().contains(gw) && s.grants[gw].active && s.grants[gw].grantor
                        == s.owner[s.maps[i].1] && s.grants[gw].grantee == s.maps[i].0
                        && s.grants[gw].frame == s.maps[i].1;
                assert(st.grants.dom().contains(gw) && st.grants[gw].active && st.grants[gw].grantor
                    == st.owner[st.maps[i].1] && st.grants[gw].grantee == st.maps[i].0
                    && st.grants[gw].frame == st.maps[i].1);
            }
        }
    }
    assert(map_identity(step(s, t)));
}

/// **`wf` preserved by `DomainDestroy`** — the cascade's own preservation obligation. The port
/// filter keeps the link map an involution (a surviving link's peer survives too — its endpoints
/// dodge `c` symmetrically); the grant filter only shrinks the table (owned frames stay owned);
/// `vaff`/`vowner` are untouched; and the `map`-identity survives because a drained map's witness
/// grant is *not* one the grant cascade revokes — its grantee dodged `c` (it survived the map
/// drain) and its grantor is the frame's owner, which cannot be `c` (the drain itself: no map
/// over a `c`-owned frame survives, which is what `drain_foreign_maps_of` establishes).
pub proof fn wf_step_destroy(s: Sys, caller: Dom, target: Dom)
    requires
        wf(s),
    ensures
        wf(step(s, Trans::Destroy { caller, target })),
{
    broadcast use vstd::set::group_set_lemmas, vstd::map::group_map_lemmas, Seq::lemma_filter_contains_rev, Seq::lemma_filter_pred;
    let t = Trans::Destroy { caller, target };
    let st = step(s, t);
    let c = target;
    if !destroy_guard(s, caller, target) {
        assert(st == s);
        assert(wf(st));
    } else {
        // ---- involution (the port cascade is reciprocity-safe) ----
        assert(involution(st.peer)) by {
            assert forall|k: Coord| st.peer.dom().contains(k) implies st.peer.dom().contains(
                st.peer[k],
            ) && st.peer[st.peer[k]] == k by {
                assert(s.peer.dom().contains(k) && k.0 != c && s.peer[k].0 != c);
                assert(st.peer[k] == s.peer[k]);
                assert(s.peer.dom().contains(s.peer[k]) && s.peer[s.peer[k]] == k);  // wf involution
                // s.peer[k] survives: its own domain != c (from k's second guard) and its peer's
                // domain == k.0 != c (from k's first guard).
                assert((s.peer[k]).0 != c && (s.peer[s.peer[k]]).0 != c);
                assert(st.peer.dom().contains(s.peer[k]) && st.peer[s.peer[k]] == s.peer[s.peer[k]]);
            }
        }
        // ---- grants name owned frames (the table only shrinks; owner is fixed) ----
        assert forall|gi: int| #![trigger st.grants[gi]] st.grants.dom().contains(gi) implies
            st.owner.dom().contains(st.grants[gi].frame) by {
            assert(s.grants.dom().contains(gi) && st.grants[gi] == s.grants[gi]);
        }
        // ---- vaff/vowner untouched ----
        assert(st.vaff.dom() == st.vowner.dom());
        // ---- map-identity (a drained map's witness grant survives the grant cascade) ----
        assert forall|i: int| 0 <= i < st.maps.len() implies #[trigger] map_backed(st, i) by {
            let x = st.maps[i];
            assert(st.maps.contains(x));  // x is at index i
            assert(s.maps.contains(x));  // filter ⊆ original (lemma_filter_contains_rev)
            // A surviving map dodged both drain arms: it is not `c`'s and not over a `c`-owned frame.
            assert(x.0 != c && s.owner[x.1] != c);  // lemma_filter_pred (the compound drain)
            let j = choose|j: int| 0 <= j < s.maps.len() && s.maps[j] == x;
            assert(map_backed(s, j));  // wf
            let gw = choose|gw: int| #![trigger s.grants[gw]]
                s.grants.dom().contains(gw) && s.grants[gw].active && s.grants[gw].grantor
                    == s.owner[s.maps[j].1] && s.grants[gw].grantee == s.maps[j].0 && s.grants[gw].frame
                    == s.maps[j].1;
            // its witness grant's grantor is the frame's owner, which the drain guarantees != c.
            assert(s.owner.dom().contains(x.1));  // grants-name-owned on gw (frame == x.1)
            // so gw dodges both revocation arms (grantor == owner[x.1] != c; grantee == x.0 != c).
            assert(!(s.grants[gw].grantor == c || (s.grants[gw].active && s.grants[gw].grantee == c)));
            assert(st.grants.dom().contains(gw) && st.grants[gw] == s.grants[gw]);
            assert(st.grants.dom().contains(gw) && st.grants[gw].active && st.grants[gw].grantor
                == st.owner[st.maps[i].1] && st.grants[gw].grantee == st.maps[i].0
                && st.grants[gw].frame == st.maps[i].1);
        }
        assert(map_identity(st));
        assert(wf(st));
    }
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

/// **Step consistency** — `obs⁺(a)`'s successor is a function of `obs⁺(a)` and the actor's
/// observation. (The meta-theorem's premise; here a discharged theorem.)
///
/// Stated over [`obs_plus`], **not** [`obs`] (⑦): confidentiality is asked over the *wider* surface,
/// because the read-closure is exactly what `a` can learn and losing a read-cap is something `a`
/// observes. Note this condition needs no channel relation at all — it is pure determinism — which
/// is why widening its surface costs nothing on the integrity side, and why the two conditions can
/// sit at different surfaces without either weakening the other.
///
/// Note also the quantification: `a` ranges over **every** domain, *including* `actor(t)`. The
/// real-code bridge used to skip that case and was thereby checking a strictly weaker property than
/// this one; ⑥ fixed the bridge to match (four channels were hiding in it).
pub open spec fn step_consistent() -> bool {
    forall|s: Sys, u: Sys, t: Trans, a: Dom|
        #![trigger obs_plus(step(s, t), a), obs_plus(step(u, t), a)]
        wf(s) && wf(u) && obs_plus(s, a) == obs_plus(u, a) && obs_plus(s, actor(t)) == obs_plus(
            u,
            actor(t),
        ) ==> obs_plus(step(s, t), a) == obs_plus(step(u, t), a)
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
                    // frame_maps: the pushed map (mapper, f) is over frame f, owned by grantor != a,
                    // so it is not one of `a`'s frame maps — the projection filter drops it.
                    broadcast use Seq::lemma_filter_push;
                    assert(!(a_frame_pred(s.owner, a))((mapper, f)));
                    assert(obs(step(s, t), a).frame_maps == obs(s, a).frame_maps);
                    // (The read-closure needs no argument here: it is not on the integrity
                    // surface — `step_consistent_holds` carries it over `obs⁺`. ⑦)
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
            Trans::Destroy { caller, target } => {
                broadcast use vstd::set::group_set_lemmas, vstd::map::group_map_lemmas,
                    vstd::map_lib::group_map_properties;
                let c = target;
                if destroy_guard(s, caller, target) {
                    // `c != a`: the destroy is authorized (`caller == c ∨ controls[caller][c]`);
                    // `c == a` would need `controls[caller][a]` (excluded by ¬interferes) or
                    // `caller == a` (excluded), so the guard could not have fired.
                    assert(c != a) by {
                        if c == a {
                            assert(s.controls.contains((caller, a)));  // guard's auth arm, caller != a
                        }
                    }
                    // `¬reach(a, c)` — the intransitive-channel heart (`no_channel_no_reach_to_c`):
                    // the peer case (`controls[caller][c]`) is excluded by ¬teardown-reach; the self
                    // case (`caller == c`) by the direct signal/consent/read terms of ¬interferes.
                    assert(!reach(s, a, c)) by {
                        if reach(s, a, c) {
                            if s.controls.contains((caller, c)) {
                                assert(teardown_reach(s, caller, a));  // witness c ⟹ interferes, ⊥
                            } else {
                                assert(caller == c);  // the guard's only other authorization arm
                            }
                        }
                    }
                    // ports: every one of `a`'s ports survives (`a != c`, and `a` holds no port
                    // toward `c`, so no `a`-port names `c` as key or value).
                    assert(!a_holds_port_toward(s, a, c));  // ¬reach
                    assert_maps_equal!(obs(step(s, t), a).peer, obs(s, a).peer, k => {
                        assert(obs(s, a).peer.dom().contains(k) == (s.peer.dom().contains(k) && k.0 == a));
                        if s.peer.dom().contains(k) && k.0 == a {
                            assert(k == (a, k.1));
                            assert(s.peer[(a, k.1)].0 != c);  // ¬a_holds_port_toward at p = k.1
                            assert(s.peer[k].0 != c);
                        }
                    });
                    // grant rows: `a`'s rows survive (grantor `a != c`; no *active* `a → c` grant).
                    assert(!a_grants_to(s, a, c));  // ¬reach
                    assert_maps_equal!(obs(step(s, t), a).grows, obs(s, a).grows, g => {
                        assert(obs(s, a).grows.dom().contains(g) == (s.grants.dom().contains(g)
                            && s.grants[g].grantor == a));
                    });
                    // frame maps: no live map is both `c`'s and over an `a`-owned frame — a `(c, f)`
                    // with `owner[f] == a` would be `map_backed` by an active `a → c` grant
                    // (`a_grants_to`), contradicting ¬reach. So the drain is a no-op on `a`'s frames.
                    assert forall|i: int| #![trigger s.maps[i]] 0 <= i < s.maps.len() implies !(
                    s.maps[i].0 == c && s.owner.dom().contains(s.maps[i].1) && s.owner[s.maps[i].1]
                        == a) by {
                        if s.maps[i].0 == c && s.owner.dom().contains(s.maps[i].1) && s.owner[s.maps[i].1]
                            == a {
                            assert(map_backed(s, i));  // wf
                            assert(a_grants_to(s, a, c));  // the witness: grantor==owner==a, grantee==c
                        }
                    }
                    compound_drain_preserves(s.maps, s.owner, a, c);
                    assert(obs(step(s, t), a).frame_maps == obs(s, a).frame_maps);
                    // (Read-caps are not on the integrity surface — ⑦. Destroying `a`'s grantor
                    // *does* drop `a`'s read-cap, but that is a confidentiality event, carried by
                    // `step_consistent_holds` over `obs⁺`, which needs no channel relation. This is
                    // exactly why the blanket `reads_from` disjunct could leave `interferes`.)
                }
                assert(obs(step(s, t), a) == obs(s, a));
            },
        }
    }
}

/// **Step consistency holds for the concrete system** (∀-N). The creation channel factors through
/// the read-closed `obs⁺`: the successor `life[a]` depends only on `life[a]` (in `obs(a)`) and
/// `may_create[creator]` (in `obs(creator)` — the GAP-C refinement); `maycreate` is unchanged.
/// Two states agreeing on both observations compute the same successor `obs⁺(a)`.
///
/// **Stated and proved over `obs⁺` (⑦).** `ObsPlus` is a two-field datatype, so the obligation
/// splits structurally into the integrity surface and the read-closure; the body establishes both
/// components per arm, and the hypothesis is likewise destructured on entry. That is the entire
/// mechanical cost of the surface split on this side — confidentiality needs no channel relation,
/// so nothing here has to be re-argued, only re-projected.
pub proof fn step_consistent_holds()
    ensures
        step_consistent(),
{
    assert forall|s: Sys, u: Sys, t: Trans, a: Dom|
        wf(s) && wf(u) && obs_plus(s, a) == obs_plus(u, a) && obs_plus(s, actor(t)) == obs_plus(
            u,
            actor(t),
        ) implies #[trigger] obs_plus(step(s, t), a) == #[trigger] obs_plus(step(u, t), a) by {
        // Destructure the hypothesis: `obs⁺` agreement is agreement on `obs` and on the read-closure.
        assert(obs(s, a) == obs(u, a));
        assert(a_read_caps(s, a) == a_read_caps(u, a));
        assert(obs(s, actor(t)) == obs(u, actor(t)));
        assert(a_read_caps(s, actor(t)) == a_read_caps(u, actor(t)));
        match t {
            Trans::Create { creator, target } => {
                // obs(·,a).live == live.contains(a); obs(·,creator).maycreate ==
                // maycreate.contains(creator). Both agree across s,u, so the guard (for target==a)
                // and the write agree; for target!=a, life[a] is untouched on both sides.
                assert(obs(step(s, t), a) == obs(step(u, t), a));
                assert(obs_plus(step(s, t), a) == obs_plus(step(u, t), a));
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
                assert(obs_plus(step(s, t), a) == obs_plus(step(u, t), a));
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
                    // The guard's `owner[f] == grantor (== a)` is observed via `a`'s owned-frame set
                    // (the role `frefs.dom` used to play): `f ∈ owned ⟺ owner.dom ∋ f ∧ owner[f]==a`.
                    assert(obs(s, a).owned.contains(f) == (s.owner.dom().contains(f) && s.owner[f] == a));
                    assert(obs(u, a).owned.contains(f) == (u.owner.dom().contains(f) && u.owner[f] == a));
                    assert(grant_map_guard(s, mapper, g) == grant_map_guard(u, mapper, g));
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
                    // Frame maps: the pushed map (mapper, f) lands in `a`'s frame maps iff the
                    // guard fires (then owner[f] == grantor == a, an `a`-frame). `f`, the map, and
                    // the guard all agree across s,u, so the pushed frame map — if any — is
                    // identical, over the obs-agreeing base populations.
                    broadcast use Seq::lemma_filter_push;
                    assert(obs(s, a).frame_maps == obs(u, a).frame_maps);
                    if grant_map_guard(s, mapper, g) {
                        assert(s.owner.dom().contains(f) && s.owner[f] == a);  // guard, grantor == a
                        assert(u.owner.dom().contains(f) && u.owner[f] == a);  // s.grants[g]==u.grants[g]
                        assert((a_frame_pred(s.owner, a))((mapper, f)));
                        assert((a_frame_pred(u.owner, a))((mapper, f)));
                    }
                    assert(obs(step(s, t), a).frame_maps == obs(step(u, t), a).frame_maps);
                } else {
                    // `g` is not one of `a`'s grant rows: the map modifies a non-`a` grant row
                    // (grantor != a) and, if the guard fires, a frame owned by that non-`a`
                    // grantor — neither in `a`'s projection. So obs(a) is unchanged on each side
                    // (the local-respect argument), and the two are equal by obs(a)-agreement.
                    assert(obs(step(s, t), a).grows =~= obs(s, a).grows);
                    assert(obs(step(u, t), a).grows =~= obs(u, a).grows);
                    // frame_maps: if a side's guard fires it pushes a map over owner[f]==grantor
                    // != a (a non-`a` frame), dropped by the projection; else no push. Each side's
                    // frame maps are therefore unchanged, and the two obs-agree.
                    broadcast use Seq::lemma_filter_push;
                    if grant_map_guard(s, mapper, g) {
                        assert(s.grants[g].grantor != a);  // ¬touches ∧ g ∈ dom (guard)
                        assert(!(a_frame_pred(s.owner, a))((mapper, s.grants[g].frame)));
                    }
                    if grant_map_guard(u, mapper, g) {
                        assert(u.grants[g].grantor != a);  // touches agrees, g ∈ dom (guard)
                        assert(!(a_frame_pred(u.owner, a))((mapper, u.grants[g].frame)));
                    }
                    assert(obs(step(s, t), a).frame_maps == obs(s, a).frame_maps);
                    assert(obs(step(u, t), a).frame_maps == obs(u, a).frame_maps);
                }
                // ---- Read-closure (the confidentiality READ direction, `read_closure.rs`) ----
                // The map touches `a`'s read-caps iff its grantee is `a` (⟺ mapper == a). Then
                // obs(a).read_caps pins the record AND the frame's `owner` (the StaleGrant read) —
                // so the guard and the count-bump are identical across s,u. This is exactly why
                // `obs⁺` must carry `owner`: without it the guard is unobserved and Verus rejects.
                broadcast use vstd::map_lib::group_map_properties;
                let reads = s.grants.dom().contains(g) && s.grants[g].grantee == a;
                assert(reads == (u.grants.dom().contains(g) && u.grants[g].grantee == a)) by {
                    assert(a_read_caps(s, a).dom().contains(g) == reads);
                    assert(a_read_caps(u, a).dom().contains(g) == (u.grants.dom().contains(g)
                        && u.grants[g].grantee == a));
                }
                if reads {
                    assert(a_read_caps(s, a)[g] == a_read_caps(u, a)[g]);
                    let fr = s.grants[g].frame;
                    // Record + frame owner pinned by the read-cap (the `owner` component).
                    assert(s.grants[g].grantor == u.grants[g].grantor && fr == u.grants[g].frame
                        && s.grants[g].active == u.grants[g].active && s.grants[g].count
                        == u.grants[g].count && s.owner[fr] == u.owner[fr]);
                    assert(s.owner.dom().contains(fr) && u.owner.dom().contains(fr));  // wf
                    assert(grant_map_guard(s, mapper, g) == grant_map_guard(u, mapper, g));
                }
                assert_maps_equal!(a_read_caps(step(s, t), a), a_read_caps(step(u, t), a), k => {
                    if k != g {
                        assert(step(s, t).grants[k] == s.grants[k]);
                        assert(step(u, t).grants[k] == u.grants[k]);
                        assert(a_read_caps(s, a).dom().contains(k) == a_read_caps(u, a).dom().contains(k));
                        if a_read_caps(s, a).dom().contains(k) {
                            assert(a_read_caps(s, a)[k] == a_read_caps(u, a)[k]);
                        }
                    }
                });
                assert(obs(step(s, t), a) == obs(step(u, t), a));
                assert(obs_plus(step(s, t), a) == obs_plus(step(u, t), a));
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
                assert(obs_plus(step(s, t), a) == obs_plus(step(u, t), a));
            },
            Trans::Destroy { caller, target } => {
                broadcast use vstd::set::group_set_lemmas, vstd::map::group_map_lemmas,
                    vstd::map_lib::group_map_properties;
                let c = target;
                // The guard reads `controls[caller][c]` — `caller`'s OWN outgoing edge, in
                // `obs(caller).controls_out` (the actor's own destroy authority). obs-agreement at
                // `caller` (= actor) pins it, so the destroy fires in both runs or neither.
                assert(destroy_guard(s, caller, target) == destroy_guard(u, caller, target)) by {
                    assert(obs(s, caller).controls_out.contains((caller, target))
                        == s.controls.contains((caller, target)));
                    assert(obs(u, caller).controls_out.contains((caller, target))
                        == u.controls.contains((caller, target)));
                }
                if destroy_guard(s, caller, target) {
                    // ---- ports ---- each of `a`'s surviving links is determined by `obs(a).peer`
                    // (its endpoints' relation to `c`) — a function of `obs(a).peer` and `c`.
                    assert_maps_equal!(obs(step(s, t), a).peer, obs(step(u, t), a).peer, k => {
                        assert(obs(s, a).peer.dom().contains(k) == (s.peer.dom().contains(k) && k.0 == a));
                        assert(obs(u, a).peer.dom().contains(k) == (u.peer.dom().contains(k) && k.0 == a));
                        assert(obs(s, a).peer.dom().contains(k) ==> obs(s, a).peer[k] == s.peer[k]);
                        assert(obs(u, a).peer.dom().contains(k) ==> obs(u, a).peer[k] == u.peer[k]);
                        assert(obs(s, a).peer.dom().contains(k) == obs(u, a).peer.dom().contains(k));
                        if obs(s, a).peer.dom().contains(k) {
                            assert(obs(s, a).peer[k] == obs(u, a).peer[k]);
                        }
                    });
                    // ---- grant rows ---- a row survives iff it dodges the revocation arms
                    // (grantor `c`, active grantee `c`) — a function of `obs(a).grows[g]`.
                    assert_maps_equal!(obs(step(s, t), a).grows, obs(step(u, t), a).grows, g => {
                        assert(obs(s, a).grows.dom().contains(g) == (s.grants.dom().contains(g)
                            && s.grants[g].grantor == a));
                        assert(obs(u, a).grows.dom().contains(g) == (u.grants.dom().contains(g)
                            && u.grants[g].grantor == a));
                        assert(obs(s, a).grows.dom().contains(g) ==> obs(s, a).grows[g] == s.grants[g]);
                        assert(obs(u, a).grows.dom().contains(g) ==> obs(u, a).grows[g] == u.grants[g]);
                        assert(obs(s, a).grows.dom().contains(g) == obs(u, a).grows.dom().contains(g));
                        if obs(s, a).grows.dom().contains(g) {
                            assert(obs(s, a).grows[g] == obs(u, a).grows[g]);
                        }
                    });
                    // ---- frame maps ---- the drain restricted to `a`'s frames is `obs(a)`'s frame
                    // maps with `c`'s dropped (or empty when `a == c`) — a function of `obs(a)`.
                    frame_maps_destroyed(s.maps, s.owner, a, c);
                    frame_maps_destroyed(u.maps, u.owner, a, c);
                    assert(obs(s, a).frame_maps == obs(u, a).frame_maps);
                    assert(obs(step(s, t), a).frame_maps == obs(step(u, t), a).frame_maps);
                    // ---- read-caps ---- a held grant survives iff grantor `≠ c` (and not an active
                    // self-grant when `a == c`) — a function of `obs(a).read_caps[g]`; `owner` fixed.
                    assert_maps_equal!(a_read_caps(step(s, t), a), a_read_caps(step(u, t), a), g => {
                        assert(a_read_caps(s, a).dom().contains(g) == (s.grants.dom().contains(g)
                            && s.grants[g].grantee == a));
                        assert(a_read_caps(u, a).dom().contains(g) == (u.grants.dom().contains(g)
                            && u.grants[g].grantee == a));
                        assert(a_read_caps(s, a).dom().contains(g) == a_read_caps(u, a).dom().contains(g));
                        if a_read_caps(s, a).dom().contains(g) {
                            assert(a_read_caps(s, a)[g] == a_read_caps(u, a)[g]);
                            assert(s.grants[g].grantor == u.grants[g].grantor
                                && s.grants[g].active == u.grants[g].active
                                && s.grants[g].grantee == u.grants[g].grantee);
                        }
                    });
                    assert(obs(step(s, t), a) == obs(step(u, t), a));
                    assert(obs_plus(step(s, t), a) == obs_plus(step(u, t), a));
                } else {
                    // Neither destroy fires: both states are unchanged and already obs(a)-agree.
                    assert(obs(step(s, t), a) == obs(step(u, t), a));
                    assert(obs_plus(step(s, t), a) == obs_plus(step(u, t), a));
                }
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

/// Two executions agree, at each step, on the acting domain's observation — at the
/// **confidentiality** surface `obs⁺` (⑦), the surface `step_consistent` is stated over.
pub open spec fn traces_agree_on_actor(s: Sys, u: Sys, tr: Seq<Trans>, a: Dom) -> bool
    decreases tr.len(),
{
    if tr.len() == 0 {
        true
    } else {
        obs_plus(s, actor(tr[0])) == obs_plus(u, actor(tr[0])) && traces_agree_on_actor(
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

/// **Theorem B (confidentiality), premise-free.** Two executions that start `obs⁺(a)`-equivalent
/// and agree at each step on the acting domain's observation stay `obs⁺(a)`-equivalent throughout.
/// Takes **no** `step_consistent()` premise — it invokes the discharged `step_consistent_holds`.
///
/// **Composed at the `obs⁺` surface (⑦), while [`ni_theorem_a`] stays at `obs`.** The two are
/// separate inductions over separate unwinding conditions, so the surfaces need not agree: each
/// theorem's induction only ever appeals to its own condition. Confidentiality reads the wider
/// surface because the read-closure is what `a` can *learn*; integrity reads the narrower one
/// because a grantor revealing itself to `a` is not something `a` is entitled to prevent.
pub proof fn ni_theorem_b(s: Sys, u: Sys, tr: Seq<Trans>, a: Dom)
    requires
        wf(s),
        wf(u),
        obs_plus(s, a) == obs_plus(u, a),
        traces_agree_on_actor(s, u, tr, a),
    ensures
        obs_plus(run(s, tr), a) == obs_plus(run(u, tr), a),
    decreases tr.len(),
{
    step_consistent_holds();
    if tr.len() > 0 {
        let act = tr[0];
        assert(obs_plus(step(s, act), a) == obs_plus(step(u, act), a));
        wf_step(s, act);
        wf_step(u, act);
        ni_theorem_b(step(s, act), step(u, act), tr.subrange(1, tr.len() as int), a);
    }
}

} // verus!
