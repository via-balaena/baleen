// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # `MislevelledLink` preserved, ∀-N — the page-table *shape* half (Phase I-2a)
//!
//! `MislevelledLink` (`hv-core/src/p2m.rs`, `System::first_violation`) is the standing hierarchy
//! invariant: every **live** page-table edge points from a table to a frame of exactly the kind the
//! entry's shape demands —
//!
//! > for every active link `l`, `current_type(l.parent)` is `PageTable(level)`, and `l.child` is the
//! > reference `entry_child_ref(level, l.leaf, l.writable)` names: a **writable leaf**'s child is
//! > `Writable`-typed, an **interior** entry's child is the `L(k-1)` table below, a **read-only
//! > leaf**'s child need only be *allocated* (a bare reference — the linear-map view, which may even
//! > point at a live page table).
//!
//! It is **load-bearing** yet, until this file, only *enumerator-checked* (plus a Tier-B locality
//! cutoff whose frame-lemma is itself a deductive obligation, `docs/TIER-B-CUTOFF.md` §2): Arc 3b's
//! `p2m_allocate` case borrows it (`foreign_link_preservation.rs`), and the Stage-2 refinement's
//! premise **P2** ("every live edge's child is allocated") rests on it
//! (`docs/STAGE2-REFINEMENT-FORALL-N.md` §7.3). Phase I-2 discharges it in Verus, ∀-N.
//!
//! ## Why `MislevelledLink` is fundamentally a *counting* proof (and how I-2 is split)
//!
//! `UnauthorizedForeignLink` (`foreign_link_preservation.rs`) reads only ownership, edges and
//! grants, so grant map/unmap and unrelated links cannot touch it. `MislevelledLink` reads
//! `current_type`, which is derived from a frame's **reference counts** (`writable_refs`,
//! `pagetable_refs`, `pt_level`). So the transition audit (design-lesson #3) splits cleanly on
//! *which* transitions move a count *down*:
//!
//! | transition | why it preserves `MislevelledLink` | needs the count coupling? |
//! |---|---|---|
//! | `p2m_link` | establishes the new edge; its two `get_type` acquires only **add** refs, and the exclusivity guard makes an add unable to flip a type | **no** — proven here |
//! | `grant_map`, `pin` | a single `get`/`get_type` acquire — **adds only** | **no** — proven here |
//! | `p2m_allocate` | a free frame gains allocation and stays untyped — purely **type-monotone** | **no** — proven here |
//! | `p2m_unlink` / `unlink_all` | a *shared* parent/child keeps its type because a **remaining** edge still holds a ref | **YES** — deferred to I-2b |
//! | `grant_unmap`, `unpin` | the frame keeps its type because a live edge still holds a ref | **YES** — deferred to I-2b |
//! | `p2m_free` | the `refs == 0` guard: a frame any live edge touches has `refs > 0` | **YES** (positivity) — deferred |
//! | `DomainDestroy` | `unlink_all` + `free_all`; **and here the `has_foreign_link_into` precondition is genuinely load-bearing** (see below) | **YES** — deferred to I-2b |
//!
//! Every decrement case preserves the invariant for the *same* reason: removing one holder
//! decrements the count *in lockstep*, so the remaining holders keep their type. That is a
//! **count↔holder coupling** — the p2m cousin of the `RefcountMismatch` relation already proven for
//! grants (`refcount_mismatch.rs`) — and, crucially, it is **not itself a checked invariant**:
//! `first_violation` never asserts "`pagetable_refs(f)` ≥ the number of edges pinning `f`". It holds
//! only *by construction* of the balanced `get`/`put` discipline. Proving `MislevelledLink` ∀-N
//! therefore surfaces a genuinely new obligation the bounded enumerator backs only by construction.
//!
//! **I-2a (this file)** proves the page-table-*shape* half outright — the additive/establishing
//! cases (`link`, `grant_map`, `pin`, `allocate`) and the base case — and states each decrement case
//! with the coupling named as an explicit hypothesis [`type_preserved_on`]: *when a holder leaves,
//! every frame still referenced by a surviving edge retains its type.* **I-2b** will prove that
//! consequence from the count↔holder lower bound (`TypeRefsAccounted`), discharging these
//! hypotheses and closing the residual. Honestly: I-2a *moves* the residual onto one named coupling
//! (design-lesson #20/#47) — closure is the committed I-2a → I-2b sequence, not I-2a alone.
//!
//! ## The one thing this file borrows from an existing checked invariant
//!
//! The additive cases lean on **exclusivity** — `¬(writable_refs > 0 ∧ pagetable_refs > 0)`, i.e.
//! `TypeConfusion` (`first_violation`), itself enumerator-checked. It is what makes an *acquire*
//! monotone: `get_type`'s conflict guard ([`get_type_incr`]'s preconditions, transcribed from
//! `p2m::System::get_type`) refuses to bump a count that would flip a live type, so an add can only
//! *establish* a type from `None` or *reinforce* the same one — never change it. That is the whole
//! reason the additive half needs no counting.
//!
//! ## A finding: for `MislevelledLink`, `DomainDestroy`'s foreign-link guard is load-bearing
//!
//! `foreign_link_preservation.rs` measured `domain_destroy`'s `has_foreign_link_into(target)`
//! precondition and its `unlink_all`-before-`revoke` ordering to be **inert** for
//! `UnauthorizedForeignLink` (that invariant *skips* an unowned-ended edge, so `free_all` alone
//! carries teardown), and localized them to "other invariants — `MislevelledLink`'s no-dangling-edge
//! content and `DeadDomainReferenced`". This file is where that localization is cashed: for
//! `MislevelledLink`, a *surviving* foreign edge whose child is one of `target`'s freed frames would
//! read `current_type == None` after `free_all` and break — exactly what `has_foreign_link_into`
//! forbids. So [`destroy_preserves`]'s [`type_preserved_on`] hypothesis is precisely where that
//! guard earns its keep, confirming the cross-file localization claim.
//!
//! ## Fidelity (a mirror, managed — the #21b discipline)
//!
//! [`current_type`], [`is_alloc`] and [`entry_child_ref`] transcribe `p2m::System::current_type` /
//! `is_allocated` / the free `entry_child_ref`; [`edge_ok`]/[`inv`] transcribe `first_violation`'s
//! hierarchy loop; [`get_type_incr`]'s preconditions transcribe `get_type`'s conflict guard. The
//! frame projection [`FrameState`] carries only `{alloc, wr, pt, lvl}` — the exact fields
//! `current_type`/`is_allocated` read; `refs` is deliberately absent (nothing here reads it — only
//! `free`'s guard does, and that is the deferred coupling's job). The enumerator pins the *same*
//! `MislevelledLink` on the real `System` at small size (`hv-sim::enumerate`, incl. the
//! `sym_hierarchy_cfg` sweep saturating at depth 16 over a full L1–L4 tree); this file adds the
//! ∀-length axis on the mirror.
//!
//! ## Non-vacuity (validated by hand; recorded in `hv-verify/verus/README.md`)
//!
//! Perturbing [`get_type_incr`] to drop the `+ 1` (an acquire that takes no reference) makes
//! [`get_type_incr_establishes`] fail; dropping its exclusivity precondition (letting a `Writable`
//! acquire fire with `pt > 0`) makes [`get_type_incr_monotone`] fail (the add would flip a live
//! page-table type). Both are the analog of the enumerator's "remove the fix → counterexample".
//!
//! Run: `verus --crate-type=lib hv-verify/verus/mislevelled_link_preservation.rs` (exit 0 = proven).

use vstd::prelude::*;

verus! {

/// A machine frame number. `int` is the honest ∀-size domain (§2.1's data-independence reduction).
type Mfn = int;

/// Mirror of `hv_core::p2m::PageType`. The page-table level is a `nat` (`L1..L4` → `1..4`); only
/// sizes matter (§2.1), so an unbounded `nat` is the honest ∀-level domain.
enum PageType {
    Writable,
    PageTable(nat),
}

/// The per-frame accounting `current_type`/`is_allocated` consult — mirror of the
/// `Frame::Allocated` fields those functions read. `refs` is **absent** on purpose: neither reads it
/// (§ fidelity), so it plays no part in this file.
struct FrameState {
    alloc: bool,
    /// `writable_refs`.
    wr: nat,
    /// `pagetable_refs`.
    pt: nat,
    /// `pt_level` — meaningful only while `pt > 0`.
    lvl: nat,
}

/// The frame table as an oracle over machine frames — the ∀-N analog of the real `Vec<Frame>` (as
/// `foreign_link_preservation::Owner` is for ownership). One transition moves one frame; the rest
/// compare equal.
type Frames = spec_fn(Mfn) -> FrameState;

/// Mirror of `p2m::System::is_allocated`.
spec fn is_alloc(fs: Frames, f: Mfn) -> bool {
    fs(f).alloc
}

/// Mirror of `p2m::System::current_type`: a frame's single live type — page tables carrying their
/// level — or `None` if free or allocated-but-untyped. Well-defined precisely because a frame is
/// never referenced as two types at once (the `TypeConfusion` exclusivity invariant).
spec fn current_type(fs: Frames, f: Mfn) -> Option<PageType> {
    if fs(f).alloc {
        if fs(f).wr > 0 {
            Some(PageType::Writable)
        } else if fs(f).pt > 0 {
            Some(PageType::PageTable(fs(f).lvl))
        } else {
            None
        }
    } else {
        None
    }
}

/// What reference an entry holds on its child — mirror of `p2m::ChildRef` + `entry_child_ref`.
/// `Invalid` is the interior-under-`L1` shape `link` refuses, so no recorded edge is ever it; it is
/// kept explicit so the invariant *fails* on it, exactly as the real check's `None => false` does.
enum ChildReq {
    Bare,
    Typed(PageType),
    Invalid,
}

/// Mirror of `hv_core::p2m::entry_child_ref`: a leaf pins `Writable` (writable) or nothing
/// (read-only — a bare existence reference); an interior entry pins the `L(k-1)` table below it.
spec fn entry_child_ref(level: nat, leaf: bool, writable: bool) -> ChildReq {
    if leaf {
        if writable {
            ChildReq::Typed(PageType::Writable)
        } else {
            ChildReq::Bare
        }
    } else if level >= 2 {
        ChildReq::Typed(PageType::PageTable((level - 1) as nat))
    } else {
        ChildReq::Invalid
    }
}

/// A live page-table edge — mirror of the active `p2m::Link` fields the hierarchy loop reads.
struct Edge {
    parent: Mfn,
    child: Mfn,
    leaf: bool,
    writable: bool,
}

/// One edge's obligation — the body of `first_violation`'s hierarchy loop, transcribed: the parent
/// is a page table at some `level`, and the child is exactly the reference the entry's shape demands.
spec fn edge_ok(e: Edge, fs: Frames) -> bool {
    match current_type(fs, e.parent) {
        Some(PageType::PageTable(level)) => match entry_child_ref(level, e.leaf, e.writable) {
            ChildReq::Bare => is_alloc(fs, e.child),
            ChildReq::Typed(ty) => current_type(fs, e.child) == Some(ty),
            ChildReq::Invalid => false,
        },
        _ => false,
    }
}

/// **The invariant.** `MislevelledLink` does not fire: every live edge is level-correct.
spec fn inv(edges: Seq<Edge>, fs: Frames) -> bool {
    forall|i: int| #![trigger edges[i]] 0 <= i < edges.len() ==> edge_ok(edges[i], fs)
}

// ─── the type-monotone core: additive transitions preserve every edge ──────────────────────────

/// `fs2` is a **type-monotone** successor of `fs`: no frame loses allocation, and no frame's
/// established type changes or vanishes. Every edge reads only "the parent is *this* table type" and
/// "the child is *this* type / allocated", so any type-monotone step preserves the whole invariant.
spec fn type_ge(fs: Frames, fs2: Frames) -> bool {
    forall|x: Mfn| #![trigger fs2(x)]
        (is_alloc(fs, x) ==> is_alloc(fs2, x)) && (current_type(fs, x) is Some ==> current_type(
            fs2,
            x,
        ) == current_type(fs, x))
}

/// The workhorse: any type-monotone step preserves `MislevelledLink`. Both borrows below
/// (`allocate`, and the additive `link`/`grant_map`/`pin`) route through this.
proof fn monotone_preserves(edges: Seq<Edge>, fs: Frames, fs2: Frames)
    requires
        inv(edges, fs),
        type_ge(fs, fs2),
    ensures
        inv(edges, fs2),
{
    assert forall|i: int| #![trigger edges[i]] 0 <= i < edges.len() implies edge_ok(
        edges[i],
        fs2,
    ) by {
        let e = edges[i];
        assert(edge_ok(e, fs));
        // The parent is a live table in `fs` (else `edge_ok(e, fs)` is false), so its type is
        // carried across identically; the child's type (or allocation) likewise.
        assert(current_type(fs, e.parent) is Some);
        assert(current_type(fs2, e.parent) == current_type(fs, e.parent));
    }
}

proof fn type_ge_refl(fs: Frames)
    ensures
        type_ge(fs, fs),
{
}

proof fn type_ge_trans(a: Frames, b: Frames, c: Frames)
    requires
        type_ge(a, b),
        type_ge(b, c),
    ensures
        type_ge(a, c),
{
    assert forall|x: Mfn| #![trigger c(x)]
        (is_alloc(a, x) ==> is_alloc(c, x)) && (current_type(a, x) is Some ==> current_type(c, x)
            == current_type(a, x)) by {
        if current_type(a, x) is Some {
            assert(current_type(b, x) == current_type(a, x));
            assert(current_type(c, x) == current_type(b, x));
        }
    }
}

/// The relation `p2m::System::get_type(m, ty)` establishes between the pre- and post-frame-tables,
/// transcribed. The preconditions are `get_type`'s **conflict guard**: a `Writable` acquire needs
/// `pt == 0`; a `PageTable(l)` acquire needs `wr == 0` and, if already page-typed, the same level.
/// That guard is exactly what makes the acquire type-monotone (it cannot bump a count that would
/// flip a live type). `alloc` and every other frame are untouched.
spec fn get_type_incr(fs: Frames, fs2: Frames, m: Mfn, ty: PageType) -> bool {
    &&& is_alloc(fs, m)
    &&& forall|x: Mfn| #![trigger fs2(x)] x != m ==> fs2(x) == fs(x)
    &&& fs2(m).alloc == fs(m).alloc
    &&& match ty {
        PageType::Writable => fs(m).pt == 0 && fs2(m).wr == fs(m).wr + 1 && fs2(m).pt == fs(m).pt
            && fs2(m).lvl == fs(m).lvl,
        PageType::PageTable(l) => fs(m).wr == 0 && (fs(m).pt == 0 || fs(m).lvl == l) && fs2(m).pt
            == fs(m).pt + 1 && fs2(m).wr == fs(m).wr && fs2(m).lvl == l,
    }
}

/// An acquire is type-monotone — the one place exclusivity (`TypeConfusion`) is used.
proof fn get_type_incr_monotone(fs: Frames, fs2: Frames, m: Mfn, ty: PageType)
    requires
        get_type_incr(fs, fs2, m, ty),
    ensures
        type_ge(fs, fs2),
{
    assert forall|x: Mfn| #![trigger fs2(x)]
        (is_alloc(fs, x) ==> is_alloc(fs2, x)) && (current_type(fs, x) is Some ==> current_type(
            fs2,
            x,
        ) == current_type(fs, x)) by {
        if x == m {
            match ty {
                PageType::Writable => {},
                PageType::PageTable(l) => {},
            }
        }
    }
}

/// An acquire *establishes* its type: after `get_type(m, ty)`, `current_type(m) == Some(ty)`.
proof fn get_type_incr_establishes(fs: Frames, fs2: Frames, m: Mfn, ty: PageType)
    requires
        get_type_incr(fs, fs2, m, ty),
    ensures
        current_type(fs2, m) == Some(ty),
{
    match ty {
        PageType::Writable => {},
        PageType::PageTable(l) => {},
    }
}

// ─── the additive / establishing transitions (proven outright) ─────────────────────────────────

/// `link`'s first step on the child, by entry shape: a typed child is `get_type`-acquired (interior
/// or writable-leaf); a read-only leaf's `get` is bare and leaves the observed frame-state
/// unchanged (nothing here reads `refs`).
spec fn child_step(cr: ChildReq, fs: Frames, fs1: Frames, child: Mfn) -> bool {
    match cr {
        ChildReq::Bare => fs1 == fs,
        ChildReq::Typed(ty) => get_type_incr(fs, fs1, child, ty),
        ChildReq::Invalid => false,
    }
}

/// **`p2m_link` — the guard establishes it; the acquires are additive.** `link` checks up front that
/// `parent` is a live table at `level` and `child` is allocated, takes the child reference the
/// entry's shape demands (`child_step`), then takes the parent self-reference
/// `get_type(parent, PageTable(level))`. Both acquires are type-monotone, so every *existing* edge
/// survives (`monotone_preserves`); the *new* edge is level-correct by construction — the parent
/// acquire keeps it `PageTable(level)`, and the child acquire makes the child exactly the demanded
/// type (or, for a read-only leaf, leaves it the allocated frame the up-front check found).
///
/// The hypotheses are `link`'s guards transcribed; `fs1` is the intermediate table after the child
/// step, `fs2` after the parent step.
proof fn link_preserves(
    edges: Seq<Edge>,
    fs: Frames,
    fs1: Frames,
    fs2: Frames,
    e: Edge,
    level: nat,
)
    requires
        inv(edges, fs),
        current_type(fs, e.parent) == Some(PageType::PageTable(level)),
        is_alloc(fs, e.child),
        entry_child_ref(level, e.leaf, e.writable) != ChildReq::Invalid,
        child_step(entry_child_ref(level, e.leaf, e.writable), fs, fs1, e.child),
        get_type_incr(fs1, fs2, e.parent, PageType::PageTable(level)),
    ensures
        inv(edges.push(e), fs2),
{
    let cr = entry_child_ref(level, e.leaf, e.writable);
    // Step 1 (child) is type-monotone: `get_type` for a typed child, identity for a bare one.
    if cr == ChildReq::Bare {
        type_ge_refl(fs);
    } else {
        let ty = choose|ty: PageType| cr == ChildReq::Typed(ty);
        assert(cr == ChildReq::Typed(ty));
        get_type_incr_monotone(fs, fs1, e.child, ty);
    }
    // Step 2 (parent) is type-monotone. Compose to `type_ge(fs, fs2)` and carry every existing edge.
    get_type_incr_monotone(fs1, fs2, e.parent, PageType::PageTable(level));
    type_ge_trans(fs, fs1, fs2);
    monotone_preserves(edges, fs, fs2);
    // The new edge `e` is level-correct in `fs2`.
    get_type_incr_establishes(fs1, fs2, e.parent, PageType::PageTable(level));
    let edges2 = edges.push(e);
    assert forall|i: int| #![trigger edges2[i]] 0 <= i < edges2.len() implies edge_ok(
        edges2[i],
        fs2,
    ) by {
        if i < edges.len() {
            assert(edges2[i] == edges[i]);
            assert(inv(edges, fs2));
        } else {
            assert(edges2[i] == e);
            assert(current_type(fs2, e.parent) == Some(PageType::PageTable(level)));
            match cr {
                ChildReq::Bare => {
                    // Read-only leaf: the child stays allocated (monotone from the up-front check).
                    assert(is_alloc(fs, e.child));
                },
                ChildReq::Typed(ty) => {
                    // Typed child: the child acquire established `ty`; step 2 carries it (monotone).
                    get_type_incr_establishes(fs, fs1, e.child, ty);
                    assert(current_type(fs1, e.child) == Some(ty));
                },
                ChildReq::Invalid => {},
            }
        }
    }
}

/// **`grant_map` (writable) / `pin` — additive.** A single `get_type` acquire is type-monotone, so
/// every edge survives. (A *read-only* grant map is a bare `get`, which leaves the observed
/// frame-state unchanged — `grant_map_bare_preserves`.)
proof fn acquire_preserves(edges: Seq<Edge>, fs: Frames, fs2: Frames, m: Mfn, ty: PageType)
    requires
        inv(edges, fs),
        get_type_incr(fs, fs2, m, ty),
    ensures
        inv(edges, fs2),
{
    get_type_incr_monotone(fs, fs2, m, ty);
    monotone_preserves(edges, fs, fs2);
}

/// **`grant_map` (read-only) — a bare `get`.** It bumps only `refs`, which no edge reads, so the
/// observed frame-state is unchanged and the invariant holds trivially.
proof fn grant_map_bare_preserves(edges: Seq<Edge>, fs: Frames, fs2: Frames)
    requires
        inv(edges, fs),
        forall|x: Mfn| #![trigger fs2(x)] fs2(x) == fs(x),
    ensures
        inv(edges, fs2),
{
    assert(type_ge(fs, fs2));
    monotone_preserves(edges, fs, fs2);
}

/// **`p2m_allocate` — purely type-monotone, and it needs *no* borrow.** A free frame `m` becomes
/// allocated and untyped (`wr == pt == 0`). No frame loses allocation or a type, so `type_ge` holds
/// outright. This is the instructive contrast with `foreign_link_preservation::allocate_preserves`:
/// that invariant reads *ownership*, which allocate changes `None → Some`, so it had to borrow
/// `MislevelledLink`'s "no live edge touches a free frame". `MislevelledLink` reads *type*, which a
/// fresh untyped frame leaves `None`, so allocation can only ever *help* — no sibling invariant is
/// needed here.
proof fn allocate_preserves(edges: Seq<Edge>, fs: Frames, fs2: Frames, m: Mfn)
    requires
        inv(edges, fs),
        !is_alloc(fs, m),
        forall|x: Mfn| #![trigger fs2(x)] x != m ==> fs2(x) == fs(x),
        is_alloc(fs2, m),
        fs2(m).wr == 0,
        fs2(m).pt == 0,
    ensures
        inv(edges, fs2),
{
    assert forall|x: Mfn| #![trigger fs2(x)]
        (is_alloc(fs, x) ==> is_alloc(fs2, x)) && (current_type(fs, x) is Some ==> current_type(
            fs2,
            x,
        ) == current_type(fs, x)) by {
        if x == m {
            // `m` was free (`current_type == None`, `is_alloc == false`), so neither clause obliges.
            assert(current_type(fs2, m) is None);
        }
    }
    monotone_preserves(edges, fs, fs2);
}

/// **The base case.** A fresh `Hypervisor` has no edges, so the invariant holds vacuously.
proof fn new_hypervisor_satisfies_inv(fs: Frames)
    ensures
        inv(Seq::<Edge>::empty(), fs),
{
}

// ─── the decrement / removal transitions (stated with the deferred coupling) ────────────────────

/// Is `x` referenced by some edge in `es` (as parent or child)? Used only in `free`'s hypothesis.
spec fn refd(es: Seq<Edge>, x: Mfn) -> bool {
    exists|i: int| #![trigger es[i]]
        0 <= i < es.len() && (es[i].parent == x || es[i].child == x)
}

/// One frame's type survives a step: it does not lose allocation, and any established type is kept.
spec fn frame_type_kept(fs: Frames, fs2: Frames, x: Mfn) -> bool {
    (is_alloc(fs, x) ==> is_alloc(fs2, x)) && (current_type(fs, x) is Some ==> current_type(fs2, x)
        == current_type(fs, x))
}

/// **The deferred coupling's consequence — `TypeRefsAccounted`, discharged in I-2b.** When one
/// reference-holder leaves (`unlink`, `unpin`, `grant_unmap`, `free`, teardown), every frame *still*
/// referenced by a surviving edge `es` retains its allocation and type — because its count stays ≥
/// the number of remaining holders. I-2a takes this as a hypothesis on each decrement lemma; I-2b
/// proves it from the count↔holder lower bound (the p2m cousin of `RefcountMismatch`), which is the
/// load-bearing counting work. Quantified over surviving-edge *ends*, so it says nothing about the
/// frames the removed holder alone touched.
spec fn type_preserved_on(es: Seq<Edge>, fs: Frames, fs2: Frames) -> bool {
    forall|k: int| #![trigger es[k]] 0 <= k < es.len() ==> frame_type_kept(fs, fs2, es[k].parent)
        && frame_type_kept(fs, fs2, es[k].child)
}

/// The removal shape argument, inlined into each subset case below (Verus does not forward a nested
/// `forall`/`exists` precondition to a sub-lemma cleanly, so the `choose` pattern of
/// `foreign_link_preservation::unlink_preserves` is written out at each site): if every surviving
/// edge `edges2` is an original edge, and each keeps its ends' types (`type_preserved_on`),
/// `MislevelledLink` holds after. The shape reasoning is uniform across the decrement cases; only how
/// I-2b discharges `type_preserved_on` differs.
///
/// **`p2m_unlink` / `unlink_all` — fewer edges, releasing the edge's references.** The surviving
/// edges are a sub-population; the released `put`/`put_type` lowers the parent's and child's counts.
/// Every *remaining* edge keeps its ends' types by [`type_preserved_on`] (I-2b: a shared frame's
/// count stays positive because a remaining holder still pins it).
proof fn unlink_preserves(edges: Seq<Edge>, edges2: Seq<Edge>, fs: Frames, fs2: Frames)
    requires
        inv(edges, fs),
        forall|j: int| #![trigger edges2[j]]
            0 <= j < edges2.len() ==> exists|i: int| #![trigger edges[i]]
                0 <= i < edges.len() && edges[i] == edges2[j],
        type_preserved_on(edges2, fs, fs2),
    ensures
        inv(edges2, fs2),
{
    assert forall|j: int| #![trigger edges2[j]] 0 <= j < edges2.len() implies edge_ok(
        edges2[j],
        fs2,
    ) by {
        let i = choose|i: int| #![trigger edges[i]]
            0 <= i < edges.len() && edges[i] == edges2[j];
        assert(edge_ok(edges[i], fs));
        assert(frame_type_kept(fs, fs2, edges2[j].parent));
        assert(frame_type_kept(fs, fs2, edges2[j].child));
    }
}

/// **`unpin` / `grant_unmap` — same edges, a released reference.** No edge is removed
/// (`edges` unchanged), but a `put_type`/`put` lowers one frame's count. Every edge keeps its ends'
/// types by [`type_preserved_on`] (I-2b: the removed holder was a pin / a grant map, above what the
/// live edges themselves pin, so the type-count stays ≥ the edges).
proof fn release_preserves(edges: Seq<Edge>, fs: Frames, fs2: Frames)
    requires
        inv(edges, fs),
        type_preserved_on(edges, fs, fs2),
    ensures
        inv(edges, fs2),
{
    assert forall|j: int| #![trigger edges[j]] 0 <= j < edges.len() implies edge_ok(
        edges[j],
        fs2,
    ) by {
        assert(edge_ok(edges[j], fs));
        assert(frame_type_kept(fs, fs2, edges[j].parent));
        assert(frame_type_kept(fs, fs2, edges[j].child));
    }
}

/// **`p2m_free` — a frame leaves the pool.** `free` un-allocates `m` (`current_type → None`), which
/// would break any edge touching `m` — but its `refs == 0` guard forbids exactly that: a frame any
/// live edge touches has `refs > 0`. That positivity is the [`type_preserved_on`] coupling in its
/// simplest form, here as the hypothesis `!refd(edges, m)`; from it, only an *un-referenced* frame
/// changes, so every edge is untouched.
proof fn free_preserves(edges: Seq<Edge>, fs: Frames, fs2: Frames, m: Mfn)
    requires
        inv(edges, fs),
        !refd(edges, m),
        forall|x: Mfn| #![trigger fs2(x)] x != m ==> fs2(x) == fs(x),
    ensures
        inv(edges, fs2),
{
    assert forall|j: int| #![trigger edges[j]] 0 <= j < edges.len() implies edge_ok(
        edges[j],
        fs2,
    ) by {
        assert(edge_ok(edges[j], fs));
        // `!refd` gives `edges[j].parent != m` and `edges[j].child != m`, so both ends are unchanged.
        assert(edges[j].parent != m);
        assert(edges[j].child != m);
        assert(fs2(edges[j].parent) == fs(edges[j].parent));
        assert(fs2(edges[j].child) == fs(edges[j].child));
    }
}

/// **`DomainDestroy` — the compound case, and where the foreign-link guard is load-bearing.**
/// Teardown runs `unlink_all(target)` (removing `target`'s own edges — the survivors are a subset)
/// and `free_all(target)` (un-allocating `target`'s frames). For `MislevelledLink`, unlike
/// `UnauthorizedForeignLink`, `free_all` un-allocating a frame that a *surviving foreign* edge still
/// points at (its child) would break the invariant — so `domain_destroy`'s
/// `has_foreign_link_into(target)` precondition is genuinely load-bearing here (§ module docs).
/// That guard is exactly what makes the [`type_preserved_on`] hypothesis hold: no surviving edge
/// references a freed frame, so every survivor keeps its type.
proof fn destroy_preserves(edges: Seq<Edge>, edges2: Seq<Edge>, fs: Frames, fs2: Frames)
    requires
        inv(edges, fs),
        forall|j: int| #![trigger edges2[j]]
            0 <= j < edges2.len() ==> exists|i: int| #![trigger edges[i]]
                0 <= i < edges.len() && edges[i] == edges2[j],
        type_preserved_on(edges2, fs, fs2),
    ensures
        inv(edges2, fs2),
{
    assert forall|j: int| #![trigger edges2[j]] 0 <= j < edges2.len() implies edge_ok(
        edges2[j],
        fs2,
    ) by {
        let i = choose|i: int| #![trigger edges[i]]
            0 <= i < edges.len() && edges[i] == edges2[j];
        assert(edge_ok(edges[i], fs));
        assert(frame_type_kept(fs, fs2, edges2[j].parent));
        assert(frame_type_kept(fs, fs2, edges2[j].child));
    }
}

} // verus!
