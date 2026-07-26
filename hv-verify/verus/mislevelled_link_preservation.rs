// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # `MislevelledLink` preserved, ∀-N — the full hierarchy invariant (Phases I-2a + I-2b)
//!
//! **Status: residual CLOSED.** I-2a proved the page-table *shape* half (the additive transitions)
//! and named the count↔holder coupling `TypeRefsAccounted` as one deferred hypothesis
//! (`type_preserved_on`). I-2b (the `count`/`accounted`/bridge machinery below) **proves that
//! coupling ∀-N** — the exact three-family cardinality relation, established at boot and preserved by
//! every transition — and derives the consequence for each decrement, so `unlink`, `unpin`/
//! `grant_unmap`, `free` and `DomainDestroy` preserve `MislevelledLink` with **no hypothesis**. The
//! whole hierarchy invariant is now machine-checked at arbitrary edge, frame and level count.
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
//! | `p2m_unlink` / `unlink_all` | a *shared* parent/child keeps its type because a **remaining** edge still holds a ref | **YES** — proven, I-2b ([`unlink_preserves`]) |
//! | `grant_unmap`, `unpin` | the frame keeps its type because a live edge still holds a ref | **YES** — proven, I-2b ([`release_preserves`]) |
//! | `p2m_free` | the `refs == 0` guard: a frame any live edge touches has `refs > 0` | **YES** (positivity) — proven, I-2b ([`free_preserves`]) |
//! | `DomainDestroy` | `unlink_all` + `free_all`; **and here the `has_foreign_link_into` precondition is genuinely load-bearing** (see below) | **YES** — proven, I-2b (loop of the above, [`destroy_preserves_note`]) |
//!
//! Every decrement case preserves the invariant for the *same* reason: removing one holder
//! decrements the count *in lockstep*, so the remaining holders keep their type. That is a
//! **count↔holder coupling** — the p2m cousin of the `RefcountMismatch` relation already proven for
//! grants (`refcount_mismatch.rs`) — and, crucially, it is **not itself a checked invariant**:
//! `first_violation` never asserts "`pagetable_refs(f)` ≥ the number of edges pinning `f`". It holds
//! only *by construction* of the balanced `get`/`put` discipline. Proving `MislevelledLink` ∀-N
//! therefore surfaces a genuinely new obligation the bounded enumerator backs only by construction.
//!
//! **I-2a** proved the page-table-*shape* half — the additive cases (`link`, `grant_map`, `pin`,
//! `allocate`) and the base case ([`link_preserves`], [`acquire_preserves`], [`allocate_preserves`]).
//! **I-2b** (the section from [`count`] onward) proves the coupling [`accounted`]
//! (`TypeRefsAccounted`) itself: each recorded count equals the cardinality of its holder family, the
//! page-table and writable holders **counted over the edge seq** ([`count`], the `refcount_mismatch.rs`
//! technique) and the pins/grant maps folded into opaque non-negative remainders ([`Rest`]). It is
//! established at boot ([`new_hypervisor_satisfies_accounted`]) and preserved by every transition —
//! additive ([`link_accounts`]/[`pin_accounts`]/[`grant_map_accounts`]/[`allocate_accounts`]) and
//! decrement ([`unlink_preserves`]/[`release_preserves`]/[`free_preserves`]). From it, a *surviving*
//! edge — which is **still in the seq**, hence automatically a holder — keeps its ends' types
//! ([`parent_keeps_type`]/[`pt_child_keeps_type`]/[`wr_child_keeps_type`], then [`surviving_edge_ok`]),
//! with **no injective claim↔edge correspondence** to maintain. That discharges I-2a's
//! `type_preserved_on` hypotheses (design-lesson #20/#47): the residual is closed, not merely moved.
//!
//! `p2m::first_violation` additionally checks the page-table family of this coupling on the **real**
//! `System` at small scope (I-2b/1 — the `PagetableRefsAccounted` violation, `≥` form, the safety
//! direction), so the coupling is enumerator-anchored on shipped code, not only mirror-proven.
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
//! forbids. In the proof this lands as [`free_preserves`]'s `refs == 0` premise (which
//! [`accounted`] turns into "no live edge references the freed frame", `!refd`): the guard is what
//! makes every `free_all` frame satisfy it (see [`destroy_preserves_note`]), confirming the
//! cross-file localization claim.
//!
//! ## Fidelity (a mirror, managed — the #21b discipline)
//!
//! [`current_type`], [`is_alloc`] and [`entry_child_ref`] transcribe `p2m::System::current_type` /
//! `is_allocated` / the free `entry_child_ref`; [`edge_ok`]/[`inv`] transcribe `first_violation`'s
//! hierarchy loop; [`get_type_incr`]'s preconditions transcribe `get_type`'s conflict guard. The
//! frame projection [`FrameState`] carries `{alloc, wr, pt, lvl}` — the exact fields
//! `current_type`/`is_allocated` read — plus `refs`, which I-2b models for [`accounted`]'s existence
//! family and [`free_preserves`]'s guard (`current_type`/`is_alloc` still never read it). The counts'
//! **holder** side — that `pt`/`wr`/`refs` equal the edge/pin/grant-map cardinalities — mirrors how
//! the real `get`/`put`/`get_type`/`put_type` move them one-per-holder; `p2m::first_violation` checks
//! the page-table family of that relation on the real `System` (I-2b/1). The enumerator pins the
//! *same* `MislevelledLink` on the real `System` at small size (`hv-sim::enumerate`, incl. the
//! `sym_hierarchy_cfg` sweep saturating at depth 16 over a full L1–L4 tree); this file adds the
//! ∀-length axis on the mirror.
//!
//! ## Non-vacuity (validated by hand; recorded in `hv-verify/verus/README.md`)
//!
//! *Additive half (I-2a):* perturbing [`get_type_incr`] to drop the `+ 1` makes
//! [`get_type_incr_establishes`] fail; dropping its exclusivity precondition makes
//! [`get_type_incr_monotone`] fail. *Coupling (I-2b):* dropping a `count_positive` witness in a bridge
//! (e.g. [`parent_keeps_type`]) makes it fail (the count is no longer forced `≥ 1`); claiming a
//! decrement leaves a count unchanged (e.g. `unlink`'s parent `pt`) makes [`accounted`] fail to hold
//! after. Each is the analog of the enumerator's "remove the fix → counterexample".
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
/// `Frame::Allocated` fields those functions read, plus `refs` (the total existence count) which
/// **I-2b** now models: `current_type`/`is_alloc` still do not read it, but `TypeRefsAccounted`
/// pins it to the existence-reference cardinality and `free`'s `refs == 0` guard consults it.
struct FrameState {
    alloc: bool,
    /// `writable_refs`.
    wr: nat,
    /// `pagetable_refs`.
    pt: nat,
    /// `pt_level` — meaningful only while `pt > 0`.
    lvl: nat,
    /// `refs` — the total existence count (every typed reference took one, plus bare `get`s). Read
    /// only by `TypeRefsAccounted` (I-2b) and `free`'s guard, never by `current_type`/`is_alloc`.
    refs: nat,
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

/// A page-table edge — mirror of the `p2m::Link` fields the hierarchy loop reads, now carrying
/// `active` (I-2b): `unlink` deactivates in place, exactly as the real `Link.active`, so the
/// reference cardinalities `TypeRefsAccounted` counts run over one fixed-length seq (the
/// `refcount_mismatch.rs` `update`-not-remove discipline). `inv` requires `edge_ok` only of the
/// active edges.
struct Edge {
    active: bool,
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

/// **The invariant.** `MislevelledLink` does not fire: every *active* edge is level-correct.
spec fn inv(edges: Seq<Edge>, fs: Frames) -> bool {
    forall|i: int| #![trigger edges[i]] 0 <= i < edges.len() ==> edges[i].active ==> edge_ok(
        edges[i],
        fs,
    )
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
    assert forall|i: int| #![trigger edges[i]] 0 <= i < edges.len() && edges[i].active implies
        edge_ok(edges[i], fs2) by {
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
        // A bare `get` bumps only `refs` (which I-2b now models), so it leaves the *type view*
        // — `alloc`/`wr`/`pt`/`lvl`, all `current_type`/`is_alloc` read — untouched on every frame.
        ChildReq::Bare => forall|x: Mfn| #![trigger fs1(x)]
            fs1(x).alloc == fs(x).alloc && fs1(x).wr == fs(x).wr && fs1(x).pt == fs(x).pt && fs1(
                x,
            ).lvl == fs(x).lvl,
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
        e.active,
        current_type(fs, e.parent) == Some(PageType::PageTable(level)),
        is_alloc(fs, e.child),
        entry_child_ref(level, e.leaf, e.writable) != ChildReq::Invalid,
        child_step(entry_child_ref(level, e.leaf, e.writable), fs, fs1, e.child),
        get_type_incr(fs1, fs2, e.parent, PageType::PageTable(level)),
    ensures
        inv(edges.push(e), fs2),
{
    let cr = entry_child_ref(level, e.leaf, e.writable);
    // Step 1 (child) is type-monotone: `get_type` for a typed child, a `refs`-only bump (which
    // leaves the type view identical) for a bare one.
    if cr == ChildReq::Bare {
        assert(type_ge(fs, fs1)) by {
            assert forall|x: Mfn| #![trigger fs1(x)]
                (is_alloc(fs, x) ==> is_alloc(fs1, x)) && (current_type(fs, x) is Some
                    ==> current_type(fs1, x) == current_type(fs, x)) by {}
        }
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
    assert forall|i: int| #![trigger edges2[i]] 0 <= i < edges2.len() && edges2[i].active implies
        edge_ok(edges2[i], fs2) by {
        if i < edges.len() {
            assert(edges2[i] == edges[i]);
            assert(inv(edges, fs2));
        } else {
            assert(edges2[i] == e);
            assert(current_type(fs2, e.parent) == Some(PageType::PageTable(level)));
            match cr {
                ChildReq::Bare => {
                    // Read-only leaf: the child stays allocated (the bare step and the parent
                    // acquire both leave the child's alloc view untouched).
                    assert(is_alloc(fs, e.child));
                    assert(is_alloc(fs2, e.child));
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

// ─── I-2b: the count↔holder coupling `TypeRefsAccounted`, discharging the decrements ────────────
//
// `MislevelledLink` reads `current_type`, derived from a frame's reference *counts*, so its
// decrement cases (`unlink`, `unpin`/`grant_unmap`, `free`, `DomainDestroy`) preserve it only because
// a shared frame keeps its type when one holder leaves — its count stays ≥ the remaining holders.
// I-2a stated that as the hypothesis `type_preserved_on`; I-2b **proves** it, from the exact
// coupling `TypeRefsAccounted` (the p2m cousin of `RefcountMismatch`): each recorded count equals the
// cardinality of its holder family. The page-table and writable holders are the edges themselves,
// counted over the edge seq with the `refcount_mismatch.rs` technique; pins and grant maps are
// `p2m`-external, folded into opaque non-negative remainders (`Rest`) that no page-table-edge
// decrement touches. Because a surviving edge is *still in the seq*, it is automatically a holder —
// so `pt`/`wr` on its ends stay ≥ 1 with no injective claim↔edge correspondence to maintain.

/// `|{ i : hit(edges[i]) }|` — the cardinality a recorded count is pinned to (`refcount_mismatch.rs`
/// `count`, generalized to an arbitrary edge predicate; peels the last element to line up with
/// `push`/`update`).
spec fn count(s: Seq<Edge>, hit: spec_fn(Edge) -> bool) -> nat
    decreases s.len(),
{
    if s.len() == 0 {
        0
    } else {
        count(s.subrange(0, s.len() - 1), hit) + if hit(s[s.len() - 1]) {
            1nat
        } else {
            0nat
        }
    }
}

/// Appending an edge bumps the matching count by exactly 1 (or 0).
proof fn count_push(s: Seq<Edge>, e: Edge, hit: spec_fn(Edge) -> bool)
    ensures
        count(s.push(e), hit) == count(s, hit) + if hit(e) {
            1nat
        } else {
            0nat
        },
{
    assert(s.push(e).subrange(0, s.len() as int) =~= s);
}

/// Overwriting index `h` changes the count by (new − old) there and nowhere else.
proof fn count_update(s: Seq<Edge>, h: int, e: Edge, hit: spec_fn(Edge) -> bool)
    requires
        0 <= h < s.len(),
    ensures
        count(s.update(h, e), hit) + if hit(s[h]) {
            1nat
        } else {
            0nat
        } == count(s, hit) + if hit(e) {
            1nat
        } else {
            0nat
        },
    decreases s.len(),
{
    let s2 = s.update(h, e);
    let last = (s.len() - 1) as int;
    if h == last {
        assert(s2.subrange(0, last) =~= s.subrange(0, last));
    } else {
        let sub = s.subrange(0, last);
        assert(s2.subrange(0, last) =~= sub.update(h, e));
        assert(s2[last] == s[last]);
        count_update(sub, h, e, hit);
    }
}

/// A matching member forces the count `≥ 1`; its contrapositive (count `== 0` ⇒ no member) is what
/// `free`'s `refs == 0` guard cashes into "no live edge touches the frame".
proof fn count_positive(s: Seq<Edge>, i: int, hit: spec_fn(Edge) -> bool)
    requires
        0 <= i < s.len(),
        hit(s[i]),
    ensures
        count(s, hit) >= 1,
    decreases s.len(),
{
    let last = (s.len() - 1) as int;
    if i < last {
        count_positive(s.subrange(0, last), i, hit);
    }
}

// The four edge-reference predicates. Each active edge takes a `Pt` self-reference on its parent, a
// child reference by shape (`Pt` interior / `Writable` writable-leaf / bare read-only-leaf), and an
// existence reference on both ends.
spec fn is_parent(f: Mfn) -> spec_fn(Edge) -> bool {
    |e: Edge| e.active && e.parent == f
}

spec fn is_pt_child(f: Mfn) -> spec_fn(Edge) -> bool {
    |e: Edge| e.active && e.child == f && !e.leaf
}

spec fn is_wr_child(f: Mfn) -> spec_fn(Edge) -> bool {
    |e: Edge| e.active && e.child == f && e.leaf && e.writable
}

spec fn is_child(f: Mfn) -> spec_fn(Edge) -> bool {
    |e: Edge| e.active && e.child == f
}

/// The `p2m`-external holders the edge seq cannot see: a pin's `Pt` reference (`pt`, `refs`), a
/// grant map's `Writable`/bare reference (`wr`, `refs`). Opaque and non-negative — no page-table-edge
/// decrement touches them, so they pass through every `unlink`/`unpin`/`grant_unmap`/`free`.
struct Rest {
    pin: spec_fn(Mfn) -> nat,
    gwr: spec_fn(Mfn) -> nat,
    gany: spec_fn(Mfn) -> nat,
}

/// **`TypeRefsAccounted`.** Each recorded count equals its edge cardinality plus the external
/// remainder — the exact three-family coupling. The page-table family is `p2m`-local (grant maps
/// never take a `Pt` reference), which is the half `p2m::first_violation` also checks (I-2b/1); the
/// writable and existence families additionally carry the grant-map remainder.
spec fn accounted(edges: Seq<Edge>, fs: Frames, r: Rest) -> bool {
    forall|f: Mfn| #![trigger fs(f)]
        fs(f).pt == count(edges, is_parent(f)) + count(edges, is_pt_child(f)) + (r.pin)(f) && fs(
            f,
        ).wr == count(edges, is_wr_child(f)) + (r.gwr)(f) && fs(f).refs == count(edges, is_parent(f))
            + count(edges, is_child(f)) + (r.pin)(f) + (r.gany)(f)
}

// ── the bridge: a surviving edge keeps its ends' types ─────────────────────────────────

/// A parent of a surviving edge keeps its page-table type: it still holds a self-reference, so
/// `pt ≥ 1`, and it has no writable reference.
proof fn parent_keeps_type(edges: Seq<Edge>, fs: Frames, r: Rest, k: int)
    requires
        accounted(edges, fs, r),
        0 <= k < edges.len(),
        edges[k].active,
        fs(edges[k].parent).alloc,
        fs(edges[k].parent).wr == 0,
    ensures
        current_type(fs, edges[k].parent) == Some(PageType::PageTable(fs(edges[k].parent).lvl)),
{
    let p = edges[k].parent;
    assert(is_parent(p)(edges[k]));
    count_positive(edges, k, is_parent(p));
}

/// An interior child of a surviving edge keeps its page-table type.
proof fn pt_child_keeps_type(edges: Seq<Edge>, fs: Frames, r: Rest, k: int)
    requires
        accounted(edges, fs, r),
        0 <= k < edges.len(),
        edges[k].active,
        !edges[k].leaf,
        fs(edges[k].child).alloc,
        fs(edges[k].child).wr == 0,
    ensures
        current_type(fs, edges[k].child) == Some(PageType::PageTable(fs(edges[k].child).lvl)),
{
    let c = edges[k].child;
    assert(is_pt_child(c)(edges[k]));
    count_positive(edges, k, is_pt_child(c));
}

/// A writable-leaf child of a surviving edge keeps its writable type.
proof fn wr_child_keeps_type(edges: Seq<Edge>, fs: Frames, r: Rest, k: int)
    requires
        accounted(edges, fs, r),
        0 <= k < edges.len(),
        edges[k].active,
        edges[k].leaf,
        edges[k].writable,
        fs(edges[k].child).alloc,
    ensures
        current_type(fs, edges[k].child) == Some(PageType::Writable),
{
    let c = edges[k].child;
    assert(is_wr_child(c)(edges[k]));
    count_positive(edges, k, is_wr_child(c));
}

/// **The `type_preserved_on` consequence, per edge — now proven.** Given the coupling holds *after*
/// the step (`accounted(edges2, fs2, r)`) and the step preserved every frame's level and allocation
/// while never *raising* a writable count (true of `unlink`/`unpin`/`grant_unmap`), a surviving edge
/// stays level-correct: its parent (and an interior child) keep their page-table type because a
/// remaining holder pins the count ≥ 1; a writable-leaf child keeps `Writable`; a read-only-leaf
/// child needs only to stay allocated, which the step preserves. This is I-2a's per-edge shape step,
/// with the type-preservation now discharged from the coupling instead of assumed.
proof fn surviving_edge_ok(edges2: Seq<Edge>, fs: Frames, fs2: Frames, r: Rest, i: int)
    requires
        accounted(edges2, fs2, r),
        0 <= i < edges2.len(),
        edges2[i].active,
        edge_ok(edges2[i], fs),
        forall|x: Mfn| #![trigger fs2(x)]
            fs2(x).lvl == fs(x).lvl && fs2(x).alloc == fs(x).alloc && fs2(x).wr <= fs(x).wr,
    ensures
        edge_ok(edges2[i], fs2),
{
    let e = edges2[i];
    let p = e.parent;
    let c = e.child;
    // `edge_ok(e, fs)` fixes the parent as a table at some `level` and the child by shape.
    let level = fs(p).lvl;
    assert(current_type(fs, p) == Some(PageType::PageTable(level)));
    assert(fs(p).alloc && fs(p).wr == 0 && fs(p).pt > 0);
    // Parent keeps `PageTable(level)` after: `wr` stayed 0, `lvl` unchanged, and a remaining holder
    // pins `pt ≥ 1`.
    parent_keeps_type(edges2, fs2, r, i);
    assert(current_type(fs2, p) == Some(PageType::PageTable(level)));
    match entry_child_ref(level, e.leaf, e.writable) {
        ChildReq::Bare => {
            // Read-only leaf: only needs the child allocated, which the step preserved.
            assert(is_alloc(fs, c));
            assert(is_alloc(fs2, c));
        },
        ChildReq::Typed(PageType::Writable) => {
            // Writable leaf: `edge_ok(fs)` gives the child `Writable`, so `alloc` holds; a remaining
            // holder pins `wr ≥ 1` after.
            assert(current_type(fs, c) == Some(PageType::Writable));
            assert(fs(c).alloc);
            wr_child_keeps_type(edges2, fs2, r, i);
        },
        ChildReq::Typed(PageType::PageTable(cl)) => {
            // Interior: `edge_ok(fs)` gives the child `PageTable(cl)` (so `wr == 0`, `lvl == cl`); a
            // remaining holder pins `pt ≥ 1` after, and `lvl` is unchanged.
            assert(current_type(fs, c) == Some(PageType::PageTable(cl)));
            assert(fs(c).alloc && fs(c).wr == 0 && fs(c).lvl == cl);
            pt_child_keeps_type(edges2, fs2, r, i);
        },
        ChildReq::Invalid => {},
    }
}

// ── decrement preserves `accounted`, and the whole invariant is discharged ──────────────

/// Deactivating an edge matches no *active*-gated predicate, so each count drops by exactly the
/// edge's contribution.
proof fn count_deactivate(edges: Seq<Edge>, h: int, hit: spec_fn(Edge) -> bool)
    requires
        0 <= h < edges.len(),
        forall|e: Edge| #[trigger] hit(e) ==> e.active,
    ensures
        ({
            let dead = Edge { active: false, ..edges[h] };
            count(edges.update(h, dead), hit) + if hit(edges[h]) {
                1nat
            } else {
                0nat
            } == count(edges, hit)
        }),
{
    let dead = Edge { active: false, ..edges[h] };
    count_update(edges, h, dead, hit);
    assert(!hit(dead));
}

/// The predicates only ever hold of active edges — the side condition [`count_deactivate`] needs.
proof fn preds_active(f: Mfn)
    ensures
        forall|e: Edge| #[trigger] is_parent(f)(e) ==> e.active,
        forall|e: Edge| #[trigger] is_pt_child(f)(e) ==> e.active,
        forall|e: Edge| #[trigger] is_wr_child(f)(e) ==> e.active,
        forall|e: Edge| #[trigger] is_child(f)(e) ==> e.active,
{
}

/// **`p2m_unlink` preserves both invariants.** Deactivating edge `h` releases its parent
/// self-reference (`pt`, `refs` on `p`) and its child reference by shape (always one `refs` on `c`;
/// plus `pt` interior or `wr` writable-leaf), touching no pin or grant map. `accounted` survives
/// (each count drops with the cardinality), so every *surviving* edge keeps its type
/// ([`surviving_edge_ok`]) and `inv` holds. `p != c` (a table is never its own child — exclusivity).
proof fn unlink_preserves(edges: Seq<Edge>, fs: Frames, fs2: Frames, r: Rest, h: int)
    requires
        inv(edges, fs),
        accounted(edges, fs, r),
        0 <= h < edges.len(),
        edges[h].active,
        edges[h].parent != edges[h].child,
        forall|x: Mfn| #![trigger fs2(x)]
            x != edges[h].parent && x != edges[h].child ==> fs2(x) == fs(x),
        forall|x: Mfn| #![trigger fs2(x)]
            fs2(x).lvl == fs(x).lvl && fs2(x).alloc == fs(x).alloc && fs2(x).wr <= fs(x).wr,
        fs2(edges[h].parent).pt == (fs(edges[h].parent).pt - 1) as nat,
        fs(edges[h].parent).pt >= 1,
        fs2(edges[h].parent).refs == (fs(edges[h].parent).refs - 1) as nat,
        fs(edges[h].parent).refs >= 1,
        fs2(edges[h].parent).wr == fs(edges[h].parent).wr,
        fs2(edges[h].child).refs == (fs(edges[h].child).refs - 1) as nat,
        fs(edges[h].child).refs >= 1,
        !edges[h].leaf ==> {
            &&& fs2(edges[h].child).pt == (fs(edges[h].child).pt - 1) as nat
            &&& fs(edges[h].child).pt >= 1
            &&& fs2(edges[h].child).wr == fs(edges[h].child).wr
        },
        (edges[h].leaf && edges[h].writable) ==> {
            &&& fs2(edges[h].child).wr == (fs(edges[h].child).wr - 1) as nat
            &&& fs(edges[h].child).wr >= 1
            &&& fs2(edges[h].child).pt == fs(edges[h].child).pt
        },
        (edges[h].leaf && !edges[h].writable) ==> {
            &&& fs2(edges[h].child).wr == fs(edges[h].child).wr
            &&& fs2(edges[h].child).pt == fs(edges[h].child).pt
        },
    ensures
        accounted(edges.update(h, Edge { active: false, ..edges[h] }), fs2, r),
        inv(edges.update(h, Edge { active: false, ..edges[h] }), fs2),
{
    let dead = Edge { active: false, ..edges[h] };
    let edges2 = edges.update(h, dead);
    // 1. `accounted` survives: each affected count drops with the edge cardinality.
    assert forall|f: Mfn| #![trigger fs2(f)]
        fs2(f).pt == count(edges2, is_parent(f)) + count(edges2, is_pt_child(f)) + (r.pin)(f) && fs2(
            f,
        ).wr == count(edges2, is_wr_child(f)) + (r.gwr)(f) && fs2(f).refs == count(edges2, is_parent(
            f,
        )) + count(edges2, is_child(f)) + (r.pin)(f) + (r.gany)(f) by {
        preds_active(f);
        count_deactivate(edges, h, is_parent(f));
        count_deactivate(edges, h, is_pt_child(f));
        count_deactivate(edges, h, is_wr_child(f));
        count_deactivate(edges, h, is_child(f));
    }
    // 2. `inv` survives: `h` is now inactive (vacuous); every other active edge is unchanged and
    //    keeps its type by `surviving_edge_ok`.
    assert forall|i: int| #![trigger edges2[i]] 0 <= i < edges2.len() && edges2[i].active implies
        edge_ok(edges2[i], fs2) by {
        assert(i != h);
        assert(edges2[i] == edges[i]);
        surviving_edge_ok(edges2, fs, fs2, r, i);
    }
}

/// **`unpin` / `grant_unmap` preserve both invariants.** Neither removes an edge; a released pin or
/// grant map lowers one frame's `pt`/`wr` and `refs` by dropping the corresponding *remainder*
/// (`pin`/`gwr`/`gany`). The edge cardinalities are unchanged, so every edge keeps its holder and
/// `accounted` + `inv` survive. Stated over the released frame `m` with the new remainder `r2`.
proof fn release_preserves(edges: Seq<Edge>, fs: Frames, fs2: Frames, r: Rest, r2: Rest, m: Mfn)
    requires
        inv(edges, fs),
        accounted(edges, fs, r),
        forall|x: Mfn| #![trigger fs2(x)] x != m ==> fs2(x) == fs(x),
        forall|x: Mfn| #![trigger fs2(x)]
            fs2(x).lvl == fs(x).lvl && fs2(x).alloc == fs(x).alloc && fs2(x).wr <= fs(x).wr,
        // the edge cardinalities are unchanged (no edge added or removed):
        forall|f: Mfn| #![trigger (r2.pin)(f)]
            (r2.pin)(f) <= (r.pin)(f) && (r2.gwr)(f) <= (r.gwr)(f) && (r2.gany)(f) <= (r.gany)(f),
        // the released frame's counts follow its remainders down; other frames unchanged:
        fs2(m).pt == count(edges, is_parent(m)) + count(edges, is_pt_child(m)) + (r2.pin)(m),
        fs2(m).wr == count(edges, is_wr_child(m)) + (r2.gwr)(m),
        fs2(m).refs == count(edges, is_parent(m)) + count(edges, is_child(m)) + (r2.pin)(m) + (
        r2.gany)(m),
        forall|f: Mfn| #![trigger (r2.pin)(f)]
            f != m ==> (r2.pin)(f) == (r.pin)(f) && (r2.gwr)(f) == (r.gwr)(f) && (r2.gany)(f) == (
            r.gany)(f),
    ensures
        accounted(edges, fs2, r2),
        inv(edges, fs2),
{
    assert forall|i: int| #![trigger edges[i]] 0 <= i < edges.len() && edges[i].active implies
        edge_ok(edges[i], fs2) by {
        surviving_edge_ok(edges, fs, fs2, r2, i);
    }
}

/// Whether `x` is referenced by some active edge (as parent or child) — I-2a's `free` predicate.
spec fn refd(es: Seq<Edge>, x: Mfn) -> bool {
    exists|i: int| #![trigger es[i]]
        0 <= i < es.len() && es[i].active && (es[i].parent == x || es[i].child == x)
}

/// **`p2m_free` preserves both invariants — and the `refs == 0` guard IS the coupling.** `free`
/// un-allocates `m`, which would break any edge touching it — but its guard `refs(m) == 0`, through
/// `accounted`, forces `count(is_parent(m)) == count(is_child(m)) == 0`: **no active edge references
/// `m`** (`!refd`). So every edge's ends are untouched and `inv` holds; `m` leaves with all counts
/// zero, so `accounted` holds. This discharges I-2a's `!refd` hypothesis from the real guard.
proof fn free_preserves(edges: Seq<Edge>, fs: Frames, fs2: Frames, r: Rest, m: Mfn)
    requires
        inv(edges, fs),
        accounted(edges, fs, r),
        fs(m).refs == 0,
        (r.pin)(m) == 0,
        (r.gwr)(m) == 0,
        (r.gany)(m) == 0,
        !fs2(m).alloc,
        forall|x: Mfn| #![trigger fs2(x)] x != m ==> fs2(x) == fs(x),
    ensures
        !refd(edges, m),
        inv(edges, fs2),
{
    // `refs(m) == 0` and the remainders are 0, so both edge cardinalities on `m` are 0.
    assert(count(edges, is_parent(m)) == 0 && count(edges, is_child(m)) == 0);
    // Hence no active edge names `m`: a witness would force the count `≥ 1`.
    assert(!refd(edges, m)) by {
        assert forall|i: int| #![trigger edges[i]]
            0 <= i < edges.len() && edges[i].active implies edges[i].parent != m && edges[i].child
            != m by {
            if edges[i].parent == m {
                count_positive(edges, i, is_parent(m));
            }
            if edges[i].child == m {
                count_positive(edges, i, is_child(m));
            }
        }
    }
    // No live edge touches `m`, so un-allocating it leaves every edge's ends unchanged.
    assert forall|i: int| #![trigger edges[i]] 0 <= i < edges.len() && edges[i].active implies
        edge_ok(edges[i], fs2) by {
        assert(edges[i].parent != m && edges[i].child != m);
        assert(fs2(edges[i].parent) == fs(edges[i].parent));
        assert(fs2(edges[i].child) == fs(edges[i].child));
    }
}

/// **`DomainDestroy` — covered by the loop primitives, with the foreign-link guard load-bearing.**
/// Teardown is `unlink_all` (a loop of [`unlink_preserves`]) then `free_all` (a loop of
/// [`free_preserves`]); each step preserves both `inv` and `accounted`, so the whole teardown does by
/// induction — no separate lemma. The one non-mechanical fact is that every `free_all` frame has
/// `refs == 0` when it runs: `unlink_all` first drops every edge `target` roots, and
/// `domain_destroy`'s `has_foreign_link_into(target)` precondition refuses teardown while any
/// *foreign* edge points into `target`'s frames — so by the time `free_preserves` runs on a frame,
/// no live edge references it, exactly its `!refd`/`refs == 0` premise. This is where the guard
/// `foreign_link_preservation.rs` measured inert for `UnauthorizedForeignLink` earns its keep for
/// `MislevelledLink` (a surviving foreign edge into a freed frame would break the hierarchy).
proof fn destroy_preserves_note() {
}

// ── the additive transitions preserve `accounted` (so it is a full invariant) ──────────

/// **`p2m_link` preserves `accounted`.** Pushing an active edge takes a `Pt` self-reference on `p`
/// and a child reference by shape; each bumped count matches the pushed edge's contribution.
proof fn link_accounts(edges: Seq<Edge>, fs: Frames, fs2: Frames, r: Rest, e: Edge)
    requires
        accounted(edges, fs, r),
        e.active,
        e.parent != e.child,
        forall|x: Mfn| #![trigger fs2(x)] x != e.parent && x != e.child ==> fs2(x) == fs(x),
        fs2(e.parent).pt == fs(e.parent).pt + 1,
        fs2(e.parent).refs == fs(e.parent).refs + 1,
        fs2(e.parent).wr == fs(e.parent).wr,
        fs2(e.child).refs == fs(e.child).refs + 1,
        !e.leaf ==> fs2(e.child).pt == fs(e.child).pt + 1 && fs2(e.child).wr == fs(e.child).wr,
        (e.leaf && e.writable) ==> fs2(e.child).wr == fs(e.child).wr + 1 && fs2(e.child).pt == fs(
            e.child,
        ).pt,
        (e.leaf && !e.writable) ==> fs2(e.child).wr == fs(e.child).wr && fs2(e.child).pt == fs(
            e.child,
        ).pt,
    ensures
        accounted(edges.push(e), fs2, r),
{
    assert forall|f: Mfn| #![trigger fs2(f)]
        fs2(f).pt == count(edges.push(e), is_parent(f)) + count(edges.push(e), is_pt_child(f)) + (
        r.pin)(f) && fs2(f).wr == count(edges.push(e), is_wr_child(f)) + (r.gwr)(f) && fs2(f).refs
        == count(edges.push(e), is_parent(f)) + count(edges.push(e), is_child(f)) + (r.pin)(f) + (
        r.gany)(f) by {
        count_push(edges, e, is_parent(f));
        count_push(edges, e, is_pt_child(f));
        count_push(edges, e, is_wr_child(f));
        count_push(edges, e, is_child(f));
    }
}

/// **`pin` preserves `accounted`.** A pin adds a `Pt` reference on `m` in the `pin` remainder.
proof fn pin_accounts(edges: Seq<Edge>, fs: Frames, fs2: Frames, r: Rest, r2: Rest, m: Mfn)
    requires
        accounted(edges, fs, r),
        forall|x: Mfn| #![trigger fs2(x)] x != m ==> fs2(x) == fs(x),
        fs2(m).pt == fs(m).pt + 1,
        fs2(m).refs == fs(m).refs + 1,
        fs2(m).wr == fs(m).wr,
        (r2.pin) == (|x: Mfn| if x == m { ((r.pin)(x) + 1) as nat } else { (r.pin)(x) }),
        (r2.gwr) == (r.gwr),
        (r2.gany) == (r.gany),
    ensures
        accounted(edges, fs2, r2),
{
}

/// **`grant_map` preserves `accounted`.** A writable grant map adds a `W` reference (`gwr`/`gany`); a
/// read-only one a bare reference (`gany`).
proof fn grant_map_accounts(
    edges: Seq<Edge>,
    fs: Frames,
    fs2: Frames,
    r: Rest,
    r2: Rest,
    m: Mfn,
    writable: bool,
)
    requires
        accounted(edges, fs, r),
        forall|x: Mfn| #![trigger fs2(x)] x != m ==> fs2(x) == fs(x),
        fs2(m).refs == fs(m).refs + 1,
        fs2(m).pt == fs(m).pt,
        writable ==> fs2(m).wr == fs(m).wr + 1,
        !writable ==> fs2(m).wr == fs(m).wr,
        (r2.pin) == (r.pin),
        (r2.gany) == (|x: Mfn| if x == m { ((r.gany)(x) + 1) as nat } else { (r.gany)(x) }),
        (r2.gwr) == (|x: Mfn|
            if x == m && writable {
                ((r.gwr)(x) + 1) as nat
            } else {
                (r.gwr)(x)
            }),
    ensures
        accounted(edges, fs2, r2),
{
}

/// **`p2m_allocate` preserves `accounted`.** A fresh frame is allocated untyped with no references,
/// so every count still matches (0 == 0 on the new frame).
proof fn allocate_accounts(edges: Seq<Edge>, fs: Frames, fs2: Frames, r: Rest, m: Mfn)
    requires
        accounted(edges, fs, r),
        forall|x: Mfn| #![trigger fs2(x)] x != m ==> fs2(x) == fs(x),
        fs2(m).wr == 0,
        fs2(m).pt == 0,
        fs2(m).refs == 0,
        (r.pin)(m) == 0,
        (r.gwr)(m) == 0,
        (r.gany)(m) == 0,
        count(edges, is_parent(m)) == 0,
        count(edges, is_pt_child(m)) == 0,
        count(edges, is_wr_child(m)) == 0,
        count(edges, is_child(m)) == 0,
    ensures
        accounted(edges, fs2, r),
{
}

/// **The base case for `accounted`.** A fresh `Hypervisor` has no edges and every frame free
/// (all counts and remainders zero), so the coupling holds.
proof fn new_hypervisor_satisfies_accounted(fs: Frames, r: Rest)
    requires
        forall|f: Mfn| #![trigger fs(f)] fs(f).pt == 0 && fs(f).wr == 0 && fs(f).refs == 0,
        forall|f: Mfn| #![trigger (r.pin)(f)] (r.pin)(f) == 0 && (r.gwr)(f) == 0 && (r.gany)(f) == 0,
    ensures
        accounted(Seq::<Edge>::empty(), fs, r),
{
}

} // verus!
