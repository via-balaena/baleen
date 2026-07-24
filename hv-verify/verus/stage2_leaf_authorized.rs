// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The Stage-2 refinement, ∀-N — every frame the emitted leaf map reaches is authorized
//!
//! Arrow (1) of the metal's isolation chain (`p2m model → leaf map → descriptor words →
//! hardware`, `hv-s2/src/lib.rs`) is the isolation content of the whole metal build: *which
//! machine frames does a domain's hardware page table reach, and at what permission?*
//! `hv-sim`'s enumerator checks it over every reachable state of its configs (828,325 states on
//! the deep grant↔p2m sweep) and `hv-fuzz` after every dispatch. Those are **bounded**, and —
//! unlike every other axis the program closed — the bound here cannot be lifted by saturation:
//! Tier B proved grant+p2m *together* is the one config whose reachable set is genuinely
//! **infinite** (`grant::map` bumps a `u32` with no cap), so its BFS frontier can never empty.
//! Deduction is not optional here; it is the only route. This file is that route's ∀-N step.
//!
//! ## The theorem
//!
//! > **T.** For every model state satisfying **(P1)** `UnauthorizedForeignLink` and **(P2)** every
//! > active edge's child is allocated, and every domain `G`: every frame the emitted leaf map
//! > reaches is one `G` **owns**, or one an **active grant** from its owner authorizes `G` for at
//! > the mapped permission.
//!
//! Proven here over an **arbitrary edge population** (`Seq<Edge>`), an arbitrary ownership
//! assignment and an arbitrary grant relation — the ∀-N axis. Kani proves the *same* statement on
//! the **shipped** `hv_s2::leaf_map_from_edges` / `hv_s2::check_authorized_with` over all edge
//! contents, ownerships, grant tables, permissions and capacities, bounded only in edge count
//! (`hv-verify/src/lib.rs::stage2_refinement`).
//!
//! ## Where the strength actually comes from — and the honest ceiling
//!
//! The interesting content is **not** the induction; it is one loop invariant:
//!
//! > every `out[m] == Some(π)` is **witnessed** by an edge with `leaf`, `owner(parent) == Some(G)`,
//! > `child == m`, `π = writable`.
//!
//! With that witness, `UnauthorizedForeignLink` — which hv-core checks over *every* edge at *every*
//! level, with the mapping domain as grantee — discharges the foreign case directly. So T is a
//! **composition**, and P1 is the load-bearing premise:
//!
//! * **P1 is cited, not proven.** `UnauthorizedForeignLink` is checked by the enumerator over every
//!   reachable state and carries a Tier-B locality cutoff (`docs/TIER-B-CUTOFF.md` §2.2: 1 edge +
//!   2 owners + 1 grant), but **no Verus proof discharges it** — it is not a machine-checked ∀-N
//!   theorem. Lifting it is Arc 3b. T is conditional on it, and saying otherwise would be exactly
//!   the overclaim class design-lesson #37 was written about.
//! * **P2 is a genuinely separate premise, not a consequence of P1.** `UnauthorizedForeignLink`
//!   *skips* an edge either of whose ends is unowned; `check_authorized` *rejects* a mapped frame
//!   nobody owns. Without P2, T is **false** at `owner(m) == None`. It holds because
//!   `p2m::link` refuses an unallocated child (`hv-core/src/p2m.rs`) and the reference the edge
//!   takes on that child blocks a later free — an argument, stated as a premise rather than left
//!   implicit.
//!
//! ## What T deliberately does NOT say (carried from `hv-s2`'s scope boundaries)
//!
//! T is **soundness, not completeness**: it forbids reaching an unauthorized frame; it does not
//! claim every authorized frame is reachable. That asymmetry is deliberate and is what makes the
//! claim true — the emitter maps only leaves of tables the domain **owns**, so a legitimately
//! shared interior node (the model permits sharing a whole subtree) yields **no** mapping beneath
//! it. That is an **under**-map: it fails **closed**. A completeness claim here would simply be
//! false.
//!
//! **Superpage size is no longer outside T (M5 Arc 6a).** It used to be — the emitter flattened a
//! model superpage into a base-page descriptor, so the size of a mapping was abstracted away. It is
//! now carried: T is proven for an ARBITRARY span filter (`span_sel`, see `selected`), so it covers
//! the base map, the super map, and any span a later arc adds, with no new proof. What remains
//! outside T: the guest-image block (infrastructure, not model-driven; proven RO+X by Kani),
//! `GuestMem` (the trusted path), and VMID/table-set binding (hv-metal). Two model states are now
//! outside the refinement's DOMAIN rather than its theorem — one frame that is a leaf at two spans,
//! and a leaf level the emitter does not encode — and both are rejected loudly rather than mapped;
//! see `hv_s2::OutOfDomain`.
//!
//! ## Fidelity (a mirror, managed — the #21b discipline)
//!
//! `emitted` mirrors `leaf_map_from_edges`'s loop, including its **overwrite** semantics: a later
//! selected edge into the same frame replaces an earlier one, so the map's value is the *last*
//! such edge (which is why the witness must be existential, not unique — both edges are
//! individually authorized, so which one wins is immaterial to T). `authorized` mirrors
//! `check_authorized_with`'s per-frame test, and P1 mirrors `first_cross_violation`'s page-table↔
//! grant scan. Three complementary axes over one obligation, none of which is the theorem alone:
//! the enumerator (real code, real reachable states, small size), Kani (real code, all values,
//! bounded edge count), Verus (this mirror, all edge counts).
//!
//! ## Non-vacuity (validated by hand; recorded in `hv-verify/verus/README.md`)
//!
//! Dropping the `owner(parent) == Some(dom)` filter from `selected`, mapping `Rw` where the edge
//! is read-only, or dropping P2 each makes Verus **reject** the proof. Note the mutation that does
//! **not** break it: dropping the `leaf` filter. That is correct and worth stating — P1 authorizes
//! *every* cross-domain edge, interior ones included, so the leaf filter carries no authorization
//! content. Its content is exactness (an interior edge must map no frame), which is
//! `hv_s2::check::check_exact`'s remit — and that is a *consistency check*, not a theorem.
//!
//! Run: `verus --crate-type=lib hv-verify/verus/stage2_leaf_authorized.rs` (exit 0 = all proven).

use vstd::prelude::*;

verus! {

/// A domain id. `int` is the honest ∀-size domain (§2.1's data-independence reduction: the core
/// branches on no literal id, so only sizes matter).
type Id = int;

/// A machine frame number.
type Mfn = int;

/// A live page-table edge, projected to what the emitter reads — mirror of
/// `p2m::link_edges()`'s `(parent, slot, child, writable, leaf)`. The slot is dropped: the
/// emitter never reads it (it keys the map by `child`), and dropping it is what makes the
/// overwrite semantics visible rather than hidden behind slot identity.
struct Edge {
    parent: Mfn,
    child: Mfn,
    writable: bool,
    leaf: bool,
}

/// Frame ownership — mirror of `p2m::owner_of`. `None` is an unallocated frame.
type Owner = spec_fn(Mfn) -> Option<Id>;

/// The grant *permit* relation — mirror of `grant::authorizes(grantor, grantee, frame, writable)`.
/// Left completely free (no monotonicity in `writable` is assumed), so the proof covers strictly
/// more relations than the grant subsystem can realise.
type Auth = spec_fn(Id, Id, Mfn, bool) -> bool;

/// An allocated frame.
spec fn allocated(o: Option<Id>) -> bool {
    match o {
        Some(_) => true,
        None => false,
    }
}

/// The emitter's edge filter: **only leaves map a frame, and only tables this domain owns are its
/// reachability** (`leaf_map_from_edges`). This one line is the whole isolation content of the
/// emitter — everything else in T is the argument that it suffices.
///
/// **`span_sel` is the M5 Arc 6a generalization, and it is what keeps this mirror faithful.** The
/// shipped emitter no longer writes one map: it routes each selected edge into the map for its
/// SPAN (base page or super page), by the level of the edge's parent. Rather than mirror two loops,
/// this proves T for an **arbitrary** span filter — so the production loop writing `base` is this
/// theorem at `span_sel = (span_of(parent) == Base)`, writing `sup` is the same theorem at
/// `== Super`, and a future third span is covered with no new proof. That is sound precisely
/// because **authorization is span-independent**: a mapped frame must be owned or granted whatever
/// the size of the mapping, so the span only decides WHICH map, never WHETHER the frame is
/// authorized. Leaving `span_sel` free (no relation to the other fields assumed) is what makes the
/// result cover every possible span assignment, exactly as the Kani harness's symbolic span does.
spec fn selected(e: Edge, owner: Owner, dom: Id, span_sel: spec_fn(Mfn) -> bool) -> bool {
    e.leaf && owner(e.parent) == Some(dom) && span_sel(e.parent)
}

/// The emitted leaf map at frame `m`, as a fold over the edge population — mirror of
/// `leaf_map_from_edges`'s loop, **including its overwrite semantics**: the last selected edge
/// into `m` wins, exactly as the real loop's `out[idx] = ...` replaces an earlier write.
///
/// The clear-to-full-capacity that opens the real loop is the `edges.len() == 0` base case: a
/// frame no edge selects is `None`, a hole — the no-stale-leaf property, structurally.
spec fn emitted(edges: Seq<Edge>, owner: Owner, dom: Id, m: Mfn, span_sel: spec_fn(Mfn) -> bool) -> Option<bool>
    decreases edges.len(),
{
    if edges.len() == 0 {
        None
    } else {
        let last = edges[edges.len() - 1];
        if selected(last, owner, dom, span_sel) && last.child == m {
            Some(last.writable)
        } else {
            emitted(edges.subrange(0, edges.len() - 1), owner, dom, m, span_sel)
        }
    }
}

/// The witness relation the loop invariant maintains: some edge in the population is a leaf of a
/// table `dom` owns, pointing at `m`, at permission `w`.
spec fn witnessed(edges: Seq<Edge>, owner: Owner, dom: Id, m: Mfn, w: bool, span_sel: spec_fn(Mfn) -> bool) -> bool {
    exists|i: int| #![trigger edges[i]]
        0 <= i < edges.len() && selected(edges[i], owner, dom, span_sel) && edges[i].child == m
            && edges[i].writable == w
}

/// **(P1) `UnauthorizedForeignLink`** — hv-core's page-table↔grant seam invariant, transcribed
/// from `hypervisor.rs::first_cross_violation`: every *cross-domain* live edge is backed by a
/// grant from the child's owner to the domain whose table maps it, at the entry's permission.
///
/// Note precisely what it does **not** cover: an edge either of whose ends is unowned is *skipped*
/// (the real check's `else { continue }`). That gap is why P2 exists as a separate premise.
spec fn no_unauthorized_foreign_link(edges: Seq<Edge>, owner: Owner, auth: Auth) -> bool {
    forall|i: int| #![trigger edges[i]]
        0 <= i < edges.len() ==> match (owner(edges[i].child), owner(edges[i].parent)) {
            (Some(co), Some(po)) => co != po ==> auth(co, po, edges[i].child, edges[i].writable),
            _ => true,
        }
}

/// **(P2) every active edge's child is allocated.** `p2m::link` refuses an unallocated child, and
/// the reference the edge takes on it blocks a later free.
spec fn edge_children_allocated(edges: Seq<Edge>, owner: Owner) -> bool {
    forall|i: int| #![trigger edges[i]]
        0 <= i < edges.len() ==> allocated(owner(edges[i].child))
}

/// The per-frame conclusion — mirror of `check_authorized_with`'s test: the domain **owns** the
/// frame, or an active grant from its owner authorizes it at the mapped permission. An
/// unallocated frame authorizes nothing, so it is `false`, matching the real checker's
/// `UnauthorizedMapping { owner: None }`.
spec fn authorized(owner: Owner, auth: Auth, dom: Id, m: Mfn, w: bool) -> bool {
    match owner(m) {
        Some(o) => o == dom || auth(o, dom, m, w),
        None => false,
    }
}

// ─── the induction ────────────────────────────────────────────────────────────────────

/// **The loop invariant, as a lemma.** Every frame the emitted map reaches is witnessed by an edge
/// that put it there. Induction peeling the last edge: either it is the writer (witness index
/// `len-1`), or the value came from the prefix and the prefix's witness lifts unchanged.
///
/// This is the whole ∀-N content of T. Everything after it is per-frame case analysis with no
/// quantifier depth — which is exactly why this obligation was tractable rather than heroic.
proof fn emitted_is_witnessed(edges: Seq<Edge>, owner: Owner, dom: Id, m: Mfn, w: bool, span_sel: spec_fn(Mfn) -> bool)
    requires
        emitted(edges, owner, dom, m, span_sel) == Some(w),
    ensures
        witnessed(edges, owner, dom, m, w, span_sel),
    decreases edges.len(),
{
    let n = edges.len() as int;
    let last = edges[n - 1];
    if selected(last, owner, dom, span_sel) && last.child == m {
        // The last edge wrote it: it is its own witness.
        assert(edges[n - 1] == last);
        assert(witnessed(edges, owner, dom, m, w, span_sel));
    } else {
        // The value survived from the prefix; lift the prefix's witness.
        let prefix = edges.subrange(0, n - 1);
        emitted_is_witnessed(prefix, owner, dom, m, w, span_sel);
        let j = choose|j: int| #![trigger prefix[j]]
            0 <= j < prefix.len() && selected(prefix[j], owner, dom, span_sel) && prefix[j].child == m
                && prefix[j].writable == w;
        assert(edges[j] == prefix[j]);
        assert(witnessed(edges, owner, dom, m, w, span_sel));
    }
}

/// **THEOREM T (per frame).** Under P1 and P2, a frame the emitted map reaches at permission `w`
/// is owned by `dom` or authorized by a grant at `w`.
///
/// The proof is the composition, in three lines: the witness edge has `owner(parent) == Some(dom)`
/// (it was *selected*), its child is allocated (P2), and if that child's owner differs from `dom`
/// then the edge is cross-domain, so P1 hands over exactly `auth(owner(m), dom, m, w)` — the
/// grantee being `owner(parent) == dom` is what makes hv-core's invariant line up with the
/// checker's question.
proof fn leaf_map_is_authorized(
    edges: Seq<Edge>,
    owner: Owner,
    auth: Auth,
    dom: Id,
    m: Mfn,
    w: bool,
    span_sel: spec_fn(Mfn) -> bool,
)
    requires
        no_unauthorized_foreign_link(edges, owner, auth),
        edge_children_allocated(edges, owner),
        emitted(edges, owner, dom, m, span_sel) == Some(w),
    ensures
        authorized(owner, auth, dom, m, w),
{
    emitted_is_witnessed(edges, owner, dom, m, w, span_sel);
    let i = choose|i: int| #![trigger edges[i]]
        0 <= i < edges.len() && selected(edges[i], owner, dom, span_sel) && edges[i].child == m
            && edges[i].writable == w;
    // P2 at the witness: the mapped frame is allocated, so it has an owner to authorize it.
    assert(allocated(owner(edges[i].child)));
    // The witness edge's parent is a table `dom` owns — this is what makes P1's *grantee*
    // (`owner(parent)`) the domain the checker is asking about.
    assert(owner(edges[i].parent) == Some(dom));
    // P1 at the witness discharges the foreign case.
    assert(match (owner(edges[i].child), owner(edges[i].parent)) {
        (Some(co), Some(po)) => co != po ==> auth(co, po, edges[i].child, edges[i].writable),
        _ => true,
    });
}

/// **THEOREM T (whole map).** The headline form: under P1 and P2, *every* frame the emitted map
/// reaches, at whatever permission, is authorized. This is `check_authorized` returning `Ok` — for
/// an arbitrary edge population, an arbitrary ownership assignment, an arbitrary grant relation,
/// and an arbitrary domain.
proof fn leaf_map_is_authorized_everywhere(edges: Seq<Edge>, owner: Owner, auth: Auth, dom: Id, span_sel: spec_fn(Mfn) -> bool)
    requires
        no_unauthorized_foreign_link(edges, owner, auth),
        edge_children_allocated(edges, owner),
    ensures
        forall|m: Mfn| #![trigger emitted(edges, owner, dom, m, span_sel)]
            emitted(edges, owner, dom, m, span_sel) is Some ==> authorized(
                owner,
                auth,
                dom,
                m,
                emitted(edges, owner, dom, m, span_sel)->Some_0,
            ),
{
    assert forall|m: Mfn| #![trigger emitted(edges, owner, dom, m, span_sel)]
        emitted(edges, owner, dom, m, span_sel) is Some implies authorized(
            owner,
            auth,
            dom,
            m,
            emitted(edges, owner, dom, m, span_sel)->Some_0,
        ) by {
        leaf_map_is_authorized(edges, owner, auth, dom, m, emitted(edges, owner, dom, m, span_sel)->Some_0, span_sel);
    }
}

// ─── the corollaries the project actually claims ──────────────────────────────────────

/// **The isolation corollary** — T stated as the sentence the metal build claims: a frame `dom`
/// neither owns nor holds any grant for is **not in the table at all**, so the guest takes a
/// translation fault rather than reaching it. Implied by T, but stated directly so the negative
/// form is machine-checked rather than left to a reader's contraposition.
proof fn an_unauthorized_frame_is_a_hole(
    edges: Seq<Edge>,
    owner: Owner,
    auth: Auth,
    dom: Id,
    m: Mfn,
    span_sel: spec_fn(Mfn) -> bool,
)
    requires
        no_unauthorized_foreign_link(edges, owner, auth),
        edge_children_allocated(edges, owner),
        owner(m) != Some(dom),
        forall|w: bool| !authorized(owner, auth, dom, m, w),
    ensures
        emitted(edges, owner, dom, m, span_sel) is None,
{
    if emitted(edges, owner, dom, m, span_sel) is Some {
        let w = emitted(edges, owner, dom, m, span_sel)->Some_0;
        leaf_map_is_authorized(edges, owner, auth, dom, m, w, span_sel);
        assert(authorized(owner, auth, dom, m, w));
    }
}

/// **No silent write escalation.** A frame mapped writable is owned by `dom` or backed by a
/// *read-write* grant — a read-only grant can never produce a writable leaf. Stated separately
/// because permission escalation, not mere reachability, is the sharper half of the isolation
/// claim (Audit #2's "RW for an RO leaf" mutation class).
proof fn a_writable_leaf_is_owned_or_rw_granted(
    edges: Seq<Edge>,
    owner: Owner,
    auth: Auth,
    dom: Id,
    m: Mfn,
    span_sel: spec_fn(Mfn) -> bool,
)
    requires
        no_unauthorized_foreign_link(edges, owner, auth),
        edge_children_allocated(edges, owner),
        emitted(edges, owner, dom, m, span_sel) == Some(true),
    ensures
        owner(m) == Some(dom) || (allocated(owner(m)) && auth(owner(m)->Some_0, dom, m, true)),
{
    leaf_map_is_authorized(edges, owner, auth, dom, m, true, span_sel);
}

/// **Totality / no stale leaf.** With no edges there is no mapping anywhere — the base case that
/// mirrors the real emitter clearing its **full capacity** before placing any leaf, which is what
/// stops a reborn tenant (M5 Arc 0) or a peer sharing a table set (M5 Arc 2) inheriting the
/// previous occupant's reach.
proof fn no_edges_maps_nothing(owner: Owner, dom: Id, m: Mfn, span_sel: spec_fn(Mfn) -> bool)
    ensures
        emitted(Seq::<Edge>::empty(), owner, dom, m, span_sel) is None,
{
}

} // verus!
