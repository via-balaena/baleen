// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # `UnauthorizedForeignLink` preserved, ∀-N — discharging Arc 3's premise
//!
//! Arc 3 proved the Stage-2 refinement theorem **T** (`stage2_leaf_authorized.rs`): every frame the
//! emitted Stage-2 leaf map reaches is owned or grant-authorized. T is **conditional** on
//! **(P1)** hv-core's `UnauthorizedForeignLink` seam invariant, and Arc 3 recorded honestly that P1
//! was *cited, not proven* — enumerator-checked over every reachable state with a Tier-B locality
//! cutoff, but discharged by no Verus proof. It was the load-bearing premise of the metal's whole
//! isolation claim and the only thing between "∀-N modulo a premise" and "∀-N".
//!
//! This file discharges it: the preservation step
//!
//! > `∀ s. INV(s) ⇒ ∀ t. INV(t(s))`
//!
//! for **every transition class that can move the system toward violating it**, at arbitrary edge
//! population, grant population and domain count.
//!
//! ## The invariant
//!
//! Transcribed from `hv-core/src/hypervisor.rs::first_cross_violation`:
//!
//! > for every **live** page-table edge, if the child's owner and the parent's owner are both
//! > known and **differ**, then the child's owner grants the parent's owner access to that frame at
//! > the entry's permission (a read-write grant for a writable entry, any grant for a read-only
//! > one).
//!
//! Two details of the real check are modelled deliberately rather than smoothed over. It scans
//! **every edge at every level** — leaf and interior alike — so the `leaf` bit is absent from
//! [`Edge`] here, exactly as the real loop binds it to `_leaf`. And it **skips** an edge either of
//! whose ends is unowned (`else { continue }`); that skip is not an oversight to be tidied away —
//! it is what makes `free` trivially safe and `allocate` the interesting case (§ below).
//!
//! ## The transition audit — which classes can move toward a violation
//!
//! The invariant reads three things: the live **edges**, the **ownership** assignment, and the
//! **grant permits**. So it can break in exactly three ways — an edge appears unauthorized, a grant
//! it relied on weakens, or an ownership change turns a same-owner edge cross-domain. Enumerating
//! every transition against those three (design-lesson #3) gives:
//!
//! | transition | why it preserves | shape |
//! |---|---|---|
//! | `p2m_link` | the seam's grant check **establishes** it for the new edge | guard |
//! | `p2m_unlink` / `unlink_all` | strictly fewer edges | monotone |
//! | `grant_access` | strictly more permits | monotone |
//! | `grant_end_access` | the `is_foreign_linked_by` block refuses **exactly** the unsafe revoke | guard |
//! | `p2m_free` / `free_all` | the freed frame's edges become **skipped** (`owner` → `None`) | structural |
//! | `p2m_allocate` | **borrows** `MislevelledLink`: no live edge touches a free frame | borrowed |
//! | `DomainDestroy` | `free_all` un-owns `target`'s frames, so its edges are **skipped** | structural |
//! | `grant` map/unmap, `DomainCreate`, evtchn, sched | do not touch edges, ownership, or permits | no-op |
//!
//! Three findings from that audit are worth stating, because each was a candidate breach that
//! turned out closed for a *different* reason — and one of them inverts the naive expectation:
//!
//! * **`free` is not a threat; `allocate` is.** The intuition is that freeing a frame out from under
//!   a live edge is the danger. It is not, *for this invariant*: `free` sets `owner` to `None`, and
//!   the invariant then **skips** that edge. The dangerous direction is the reverse — `allocate`
//!   can take an edge from *skipped* to *checked*. That is ruled out only because no live edge can
//!   touch a free frame, which is `MislevelledLink`'s content, not this invariant's. So preservation
//!   here **borrows from a relational invariant** — the third occurrence of the shape the Kani spike
//!   first found for `WritableExceedsMaps` (design-lesson #20).
//! * **An in-place grant downgrade would break it, and is unrepresentable.** Weakening a live
//!   read-write grant to read-only under a writable edge would falsify the invariant with no guard
//!   anywhere in sight. `grant::grant_access` refuses unless the entry is `Free`, so a grant is
//!   never overwritten in place — the only weakening path is `end_access`, which *is* guarded.
//! * **The `end_access` block is exact, not merely conservative.** `p2m::is_foreign_linked_by(frame,
//!   grantee)` — "some live edge has `child == frame`, a parent owned by `grantee`, and `grantee` is
//!   not the frame's owner" — matches the invariant's violation condition term for term, with the
//!   revoked grant's `(frame, grantee)` as `(child, parent_owner)`. `end_access_preserves` below is
//!   stated with that block verbatim as its hypothesis.
//!
//! ## What this buys, and what it does not
//!
//! With this file, Arc 3's **T becomes unconditional on P1** — both are now ∀-N Verus theorems, and
//! T's remaining premise **P2** (every live edge's child is allocated) turns out to be *implied by*
//! `MislevelledLink` rather than needing its own argument (a typed child is allocated; the bare-ref
//! case checks `is_allocated` directly).
//!
//! What it does **not** buy, stated so the ledger stays honest: this is the **preservation step**,
//! `INV(s) ⇒ INV(t(s))`. Together with the base case (`Hypervisor::new` starts with no edges and no
//! grants, so the invariant holds vacuously) it gives induction over reachable states — but the
//! *initiation* and the claim that this transition list is **complete** are arguments, not
//! machine-checked facts: nothing here proves the enumeration in the table above missed no
//! transition. What backs completeness is the audit (design-lesson #3, applied above) plus the
//! enumerator, which checks the real `first_cross_violation` after **every** dispatch of **every**
//! transition over every reachable state of its configs — so a missed class would have to be one
//! the enumerator also never drives. And `MislevelledLink`, now load-bearing for the `allocate`
//! case, is itself enumerator-checked, not Verus-proven: the borrow moves the residual, it does not
//! erase it.
//!
//! ## Fidelity (a mirror, managed — the #21b discipline)
//!
//! [`inv`] mirrors `first_cross_violation`'s page-table↔grant loop including the unowned-end skip;
//! [`authorizes`] mirrors `grant::System::authorizes` (a scan of the grantor's live entries for a
//! matching grantee + frame, read-write only if `!readonly`). Each lemma's hypotheses are the real
//! guard, transcribed: `p2m_link`'s seam check, `grant_end_access`'s `is_foreign_linked_by` block,
//! `domain_destroy`'s `has_foreign_link_into` precondition and its teardown ordering. The
//! enumerator pins the same invariant on the real `Hypervisor` at small size; Kani drives the real
//! `Hypervisor` through `dispatch` at bounded size (`hv-verify::foreign_link_state_machine`).
//!
//! ## Non-vacuity (validated by hand; recorded in `hv-verify/verus/README.md`)
//!
//! Dropping the seam's grant check from `link_preserves`, the `is_foreign_linked_by` block from
//! `end_access_preserves`, or the no-live-edge-touches-a-free-frame hypothesis from
//! `allocate_preserves` each makes Verus **reject** the proof.
//!
//! Two mutations **do not** fire, and both are recorded rather than buried, because each localizes
//! a guard to the invariant that actually owns it. `domain_destroy`'s **`has_foreign_link_into`
//! precondition** and its **`unlink_all`-before-`revoke_grants_to` ordering** were both written as
//! hypotheses of `destroy_preserves` on the expectation that they were load-bearing — and removing
//! either leaves the proof green. The reason is the same skip that makes `free` safe: `free_all`
//! un-owns `target`'s frames, so every edge touching `target` is skipped, precondition or not. Both
//! guards are therefore *not* hypotheses of the lemma (a lemma should require what it uses); they
//! remain load-bearing for `MislevelledLink` (no dangling edge) and `DeadDomainReferenced` (a
//! reborn slot inherits nothing), which is where they belong.
//!
//! Run: `verus --crate-type=lib hv-verify/verus/foreign_link_preservation.rs` (exit 0 = all proven).

use vstd::prelude::*;

verus! {

/// A domain id. `int` is the honest ∀-size domain (§2.1's data-independence reduction).
type Id = int;

/// A machine frame number.
type Mfn = int;

/// A live page-table edge, projected to what the seam reads. **No `leaf` bit**: the real check
/// binds it to `_leaf` and scans every edge at every level, leaf and interior alike — which is
/// exactly why one grant of a shared node authorizes the whole subtree beneath it.
struct Edge {
    parent: Mfn,
    child: Mfn,
    writable: bool,
}

/// A live grant permit — mirror of `GrantEntry::Access`'s authorization-relevant fields. The
/// `maps`/`writable_maps` refcounts are absent on purpose: `authorizes` does not read them, so
/// grant map/unmap cannot affect this invariant at all.
struct Grant {
    grantor: Id,
    grantee: Id,
    frame: Mfn,
    readonly: bool,
}

/// Frame ownership — mirror of `p2m::owner_of`. `None` is an unallocated frame.
type Owner = spec_fn(Mfn) -> Option<Id>;

/// Mirror of `grant::System::authorizes`: does `grantor` currently offer `grantee` an active grant
/// of `frame` — and, if `writable` is asked, a read-*write* one?
spec fn authorizes(gs: Seq<Grant>, grantor: Id, grantee: Id, frame: Mfn, writable: bool) -> bool {
    exists|i: int| #![trigger gs[i]]
        0 <= i < gs.len() && gs[i].grantor == grantor && gs[i].grantee == grantee && gs[i].frame
            == frame && (!writable || !gs[i].readonly)
}

/// One edge's obligation — the body of `first_cross_violation`'s loop. Note the **skip**: an edge
/// either of whose ends is unowned imposes nothing.
spec fn edge_ok(e: Edge, owner: Owner, gs: Seq<Grant>) -> bool {
    match (owner(e.child), owner(e.parent)) {
        (Some(co), Some(po)) => co != po ==> authorizes(gs, co, po, e.child, e.writable),
        _ => true,
    }
}

/// **The invariant.** `UnauthorizedForeignLink` does not fire: every live cross-domain edge is
/// backed by a matching grant.
spec fn inv(edges: Seq<Edge>, owner: Owner, gs: Seq<Grant>) -> bool {
    forall|i: int| #![trigger edges[i]] 0 <= i < edges.len() ==> edge_ok(edges[i], owner, gs)
}

// ─── grant-population plumbing ────────────────────────────────────────────────────────

/// `gs2` retains every grant of `gs` except (possibly) index `k` — the abstract shape of
/// `end_access` removing one entry. Stated as retention rather than `Seq::remove` so the lemma
/// covers the real sweeps (`revoke_all`, `revoke_grants_to`) that remove several at once.
spec fn retains_except(gs: Seq<Grant>, gs2: Seq<Grant>, k: int) -> bool {
    forall|i: int| #![trigger gs[i]]
        0 <= i < gs.len() && i != k ==> exists|j: int| #![trigger gs2[j]]
            0 <= j < gs2.len() && gs2[j] == gs[i]
}

/// An authorization whose witness survives into `gs2` still holds there. The workhorse behind every
/// grant-removal case: `authorizes` is an existential over the population, so preservation is a
/// question of whether *some* witness survives, never of which one.
proof fn authorizes_transfers(
    gs: Seq<Grant>,
    gs2: Seq<Grant>,
    grantor: Id,
    grantee: Id,
    frame: Mfn,
    writable: bool,
    j: int,
)
    requires
        0 <= j < gs.len(),
        gs[j].grantor == grantor,
        gs[j].grantee == grantee,
        gs[j].frame == frame,
        !writable || !gs[j].readonly,
        exists|q: int| #![trigger gs2[q]] 0 <= q < gs2.len() && gs2[q] == gs[j],
    ensures
        authorizes(gs2, grantor, grantee, frame, writable),
{
    let q = choose|q: int| #![trigger gs2[q]] 0 <= q < gs2.len() && gs2[q] == gs[j];
    assert(gs2[q] == gs[j]);
}

// ─── the transition classes ───────────────────────────────────────────────────────────

/// **`p2m_link` — the guard establishes it.** The seam checks, before touching `p2m`, that a child
/// owned by anyone but the caller is covered by a grant at the entry's permission; `p2m::link`
/// independently requires the caller to own `parent`, so the caller *is* the new edge's
/// `parent_owner` — which is what makes the seam's grantee line up with the invariant's.
///
/// The hypothesis below is that check, transcribed. Adding the edge preserves the invariant, and no
/// other edge, owner or grant moves.
proof fn link_preserves(edges: Seq<Edge>, owner: Owner, gs: Seq<Grant>, e: Edge, caller: Id)
    requires
        inv(edges, owner, gs),
        owner(e.parent) == Some(caller),
        // The seam's guard: a foreign child needs a matching grant from its owner to the caller.
        match owner(e.child) {
            Some(co) => co != caller ==> authorizes(gs, co, caller, e.child, e.writable),
            None => true,
        },
    ensures
        inv(edges.push(e), owner, gs),
{
    let edges2 = edges.push(e);
    assert forall|i: int| #![trigger edges2[i]] 0 <= i < edges2.len() implies edge_ok(
        edges2[i],
        owner,
        gs,
    ) by {
        if i < edges.len() {
            assert(edges2[i] == edges[i]);
        } else {
            assert(edges2[i] == e);
        }
    }
}

/// **`p2m_unlink` / `unlink_all` — monotone.** Any sub-population of a satisfying edge set
/// satisfies it: removing edges can only remove obligations. Stated over an arbitrary subset so it
/// covers the bulk sweep as well as the single unlink.
proof fn unlink_preserves(edges: Seq<Edge>, edges2: Seq<Edge>, owner: Owner, gs: Seq<Grant>)
    requires
        inv(edges, owner, gs),
        forall|j: int| #![trigger edges2[j]]
            0 <= j < edges2.len() ==> exists|i: int| #![trigger edges[i]]
                0 <= i < edges.len() && edges[i] == edges2[j],
    ensures
        inv(edges2, owner, gs),
{
    assert forall|j: int| #![trigger edges2[j]] 0 <= j < edges2.len() implies edge_ok(
        edges2[j],
        owner,
        gs,
    ) by {
        let i = choose|i: int| #![trigger edges[i]]
            0 <= i < edges.len() && edges[i] == edges2[j];
        assert(edge_ok(edges[i], owner, gs));
    }
}

/// **`grant_access` — monotone.** Offering a grant only ever *adds* authorizations, so every
/// existing obligation still discharges. (This is also why the invariant needs no guard on the
/// grant side at mint time: only *removal* is dangerous.)
proof fn grant_access_preserves(edges: Seq<Edge>, owner: Owner, gs: Seq<Grant>, g: Grant)
    requires
        inv(edges, owner, gs),
    ensures
        inv(edges, owner, gs.push(g)),
{
    let gs2 = gs.push(g);
    assert forall|i: int| #![trigger edges[i]] 0 <= i < edges.len() implies edge_ok(
        edges[i],
        owner,
        gs2,
    ) by {
        assert(edge_ok(edges[i], owner, gs));
        match (owner(edges[i].child), owner(edges[i].parent)) {
            (Some(co), Some(po)) => {
                if co != po {
                    let j = choose|j: int| #![trigger gs[j]]
                        0 <= j < gs.len() && gs[j].grantor == co && gs[j].grantee == po && gs[j].frame
                            == edges[i].child && (!edges[i].writable || !gs[j].readonly);
                    assert(gs2[j] == gs[j]);
                }
            },
            _ => {},
        }
    }
}

/// **`grant_end_access` — the block refuses exactly the unsafe revoke.** The seam refuses to revoke
/// grant `k` while `p2m::is_foreign_linked_by(gs[k].frame, gs[k].grantee)` holds. That predicate is
/// the hypothesis below, negated and transcribed term for term.
///
/// The argument is sharper than "the block is conservative": if the revoked grant were the *sole*
/// witness for some cross-domain edge, that edge would have `child == gs[k].frame`, a parent owned
/// by `gs[k].grantee`, and a child owner differing from it — i.e. it would satisfy the blocked
/// predicate exactly. So under the block, `gs[k]` witnesses **no** cross-domain edge at all, and
/// every obligation's witness is some other grant, which survives.
proof fn end_access_preserves(
    edges: Seq<Edge>,
    owner: Owner,
    gs: Seq<Grant>,
    gs2: Seq<Grant>,
    k: int,
)
    requires
        inv(edges, owner, gs),
        0 <= k < gs.len(),
        retains_except(gs, gs2, k),
        // `!is_foreign_linked_by(gs[k].frame, gs[k].grantee)`, transcribed.
        forall|i: int| #![trigger edges[i]]
            0 <= i < edges.len() ==> !(edges[i].child == gs[k].frame && owner(edges[i].parent)
                == Some(gs[k].grantee) && owner(edges[i].child) != Some(gs[k].grantee)),
    ensures
        inv(edges, owner, gs2),
{
    assert forall|i: int| #![trigger edges[i]] 0 <= i < edges.len() implies edge_ok(
        edges[i],
        owner,
        gs2,
    ) by {
        assert(edge_ok(edges[i], owner, gs));
        match (owner(edges[i].child), owner(edges[i].parent)) {
            (Some(co), Some(po)) => {
                if co != po {
                    let j = choose|j: int| #![trigger gs[j]]
                        0 <= j < gs.len() && gs[j].grantor == co && gs[j].grantee == po && gs[j].frame
                            == edges[i].child && (!edges[i].writable || !gs[j].readonly);
                    // `j == k` would make this edge satisfy the blocked predicate exactly:
                    // child == gs[k].frame, parent owned by gs[k].grantee, child owner co != po.
                    assert(j != k);
                    authorizes_transfers(
                        gs,
                        gs2,
                        co,
                        po,
                        edges[i].child,
                        edges[i].writable,
                        j,
                    );
                }
            },
            _ => {},
        }
    }
}

/// **`p2m_free` / `free_all` — structural, and the direction that surprises.** Freeing a frame sets
/// its owner to `None`, and the invariant **skips** any edge with an unowned end. So freeing a
/// frame that a live edge still touches cannot violate *this* invariant at all — no guard needed,
/// no hypothesis about references. (It would violate `MislevelledLink`; that is a different
/// invariant with its own guard, and conflating the two is how one ends up "proving" a premise that
/// was never at risk.)
proof fn free_preserves(
    edges: Seq<Edge>,
    owner: Owner,
    owner2: Owner,
    gs: Seq<Grant>,
    freed: Id,
)
    requires
        inv(edges, owner, gs),
        // Every frame `freed` owned becomes unowned; every other frame keeps its owner.
        forall|x: Mfn| #![trigger owner2(x)]
            if owner(x) == Some(freed) {
                owner2(x) is None
            } else {
                owner2(x) == owner(x)
            },
    ensures
        inv(edges, owner2, gs),
{
    assert forall|i: int| #![trigger edges[i]] 0 <= i < edges.len() implies edge_ok(
        edges[i],
        owner2,
        gs,
    ) by {
        assert(edge_ok(edges[i], owner, gs));
        assert(owner2(edges[i].child) is Some ==> owner2(edges[i].child) == owner(edges[i].child));
        assert(owner2(edges[i].parent) is Some ==> owner2(edges[i].parent) == owner(
            edges[i].parent,
        ));
    }
}

/// **`p2m_allocate` — the interesting case, and it borrows.** Allocating a free frame can take an
/// edge from *skipped* (an unowned end) to *checked*, which is the one ownership move that can
/// create an obligation out of nothing. It is safe only because **no live edge touches a free
/// frame** — which is `MislevelledLink`'s content (a live edge's parent is a typed table and its
/// child is allocated), not this invariant's.
///
/// So this lemma is *conditional on a sibling invariant*, exactly the shape design-lesson #20 named:
/// a seam invariant's inductiveness borrowing from a structural one. The hypothesis is stated, not
/// assumed away.
proof fn allocate_preserves(
    edges: Seq<Edge>,
    owner: Owner,
    owner2: Owner,
    gs: Seq<Grant>,
    m: Mfn,
    d: Id,
)
    requires
        inv(edges, owner, gs),
        owner(m) is None,
        owner2(m) == Some(d),
        forall|x: Mfn| #![trigger owner2(x)] x != m ==> owner2(x) == owner(x),
        // Borrowed from `MislevelledLink`: a free frame is neither end of any live edge.
        forall|i: int| #![trigger edges[i]]
            0 <= i < edges.len() ==> edges[i].parent != m && edges[i].child != m,
    ensures
        inv(edges, owner2, gs),
{
    assert forall|i: int| #![trigger edges[i]] 0 <= i < edges.len() implies edge_ok(
        edges[i],
        owner2,
        gs,
    ) by {
        assert(edge_ok(edges[i], owner, gs));
        assert(edges[i].child != m && edges[i].parent != m);
    }
}

/// **`DomainDestroy` — the compound case, and the hypotheses it turns out **not** to need.**
/// Teardown is the only transition that removes edges, revokes grants (both offered *and* received)
/// and un-owns frames at once, so it is the only one where the invariant could break *between* its
/// own steps.
///
/// The expectation going in was that two guards in the real `domain_destroy` would be load-bearing
/// here: the **precondition** `!has_foreign_link_into(target)`, and the **ordering** that runs
/// `unlink_all(target)` before `revoke_grants_to(target)` (whose rationale the source comments state
/// explicitly). Both were stated as hypotheses, and **both were then measured to be unnecessary** —
/// dropping either leaves the proof green (`hv-verify/verus/README.md`). They are therefore *not*
/// hypotheses of this lemma, because a lemma should require what it uses.
///
/// The single reason teardown preserves *this* invariant is `free_all`: it un-owns every frame
/// `target` held, and the invariant **skips** any edge with an unowned end. So every edge touching
/// `target` at either end — including exactly the foreign links the precondition forbids, and
/// exactly the `target`-parented edges the ordering removes early — is skipped rather than
/// unauthorized. Every *surviving* cross-domain edge runs between two other domains, so its witness
/// grant names `target` as neither grantor nor grantee and both revoke sweeps spare it.
///
/// This does not make those guards pointless — it **localizes** them. They are load-bearing for
/// other properties (not yanking a page out from under a foreign mapper, i.e. `MislevelledLink`'s
/// no-dangling-edge content; and `DeadDomainReferenced`'s "a reborn slot inherits nothing"). Finding
/// that out is the point of stating a guard as a hypothesis and then trying to remove it.
///
/// Hypotheses are stated abstractly (retention/containment rather than a particular sweep) so the
/// lemma covers the real `unlink_all` / `revoke_all` / `revoke_grants_to` / `free_all` however they
/// iterate.
proof fn destroy_preserves(
    edges: Seq<Edge>,
    edges2: Seq<Edge>,
    owner: Owner,
    owner2: Owner,
    gs: Seq<Grant>,
    gs2: Seq<Grant>,
    target: Id,
)
    requires
        inv(edges, owner, gs),
        // `unlink_all(target)`: every survivor is an original edge. Note what is *absent* — no
        // constraint that its parent is not `target`'s, and no foreign-link precondition.
        forall|j: int| #![trigger edges2[j]]
            0 <= j < edges2.len() ==> exists|i: int| #![trigger edges[i]]
                0 <= i < edges.len() && edges[i] == edges2[j],
        // `revoke_all(target)` + `revoke_grants_to(target)`: every grant touching `target` as
        // grantor or grantee may go; every other grant survives.
        forall|i: int| #![trigger gs[i]]
            0 <= i < gs.len() && gs[i].grantor != target && gs[i].grantee != target ==> exists|
                j: int,
            | #![trigger gs2[j]] 0 <= j < gs2.len() && gs2[j] == gs[i],
        // `free_all(target)`: `target`'s frames become unowned; every other frame keeps its owner.
        forall|x: Mfn| #![trigger owner2(x)]
            if owner(x) == Some(target) {
                owner2(x) is None
            } else {
                owner2(x) == owner(x)
            },
    ensures
        inv(edges2, owner2, gs2),
{
    assert forall|j: int| #![trigger edges2[j]] 0 <= j < edges2.len() implies edge_ok(
        edges2[j],
        owner2,
        gs2,
    ) by {
        let i = choose|i: int| #![trigger edges[i]]
            0 <= i < edges.len() && edges[i] == edges2[j];
        assert(edge_ok(edges[i], owner, gs));
        match (owner2(edges2[j].child), owner2(edges2[j].parent)) {
            (Some(co), Some(po)) => {
                if co != po {
                    // Both ends survived the free, so neither is one of `target`'s frames and both
                    // owners are unchanged. In particular `co != target` and `po != target`.
                    assert(owner(edges2[j].child) == Some(co) && co != target);
                    assert(owner(edges2[j].parent) == Some(po) && po != target);
                    let q = choose|q: int| #![trigger gs[q]]
                        0 <= q < gs.len() && gs[q].grantor == co && gs[q].grantee == po && gs[q].frame
                            == edges[i].child && (!edges[i].writable || !gs[q].readonly);
                    // The witness names neither `target` as grantor nor as grantee, so the
                    // teardown's two revoke sweeps both spare it.
                    assert(gs[q].grantor != target && gs[q].grantee != target);
                    authorizes_transfers(
                        gs,
                        gs2,
                        co,
                        po,
                        edges2[j].child,
                        edges2[j].writable,
                        q,
                    );
                }
            },
            _ => {},
        }
    }
}

/// **The base case.** A fresh `Hypervisor` has no edges, so the invariant holds vacuously — the
/// initiation half of the induction whose step the lemmas above discharge.
proof fn new_hypervisor_satisfies_inv(owner: Owner, gs: Seq<Grant>)
    ensures
        inv(Seq::<Edge>::empty(), owner, gs),
{
}

} // verus!
