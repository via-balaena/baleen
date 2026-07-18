// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Tier C / Verus — the control-forest is acyclic, at arbitrary domain count
//!
//! The **third and last** §3 residual (`docs/TIER-B-CUTOFF.md` §2.4, §3(3)), and the one Tier B
//! flagged as having *no size cutoff at all*. `ControlEdgeOrphaned` (`hv-core/src/hypervisor.rs`,
//! `first_cross_violation`) walks a control edge's provenance up the delegation tree — each
//! `Via(d)` points at the delegator `d` — and requires it to reach a creation `Root` within
//! `domain_count` steps. It splits into two cases:
//!
//! * **Orphan** (a `Via(d)` whose delegator's cell went `Absent`): local, witness = 3 domains —
//!   Tier B's cutoff covers it (§2.2). *Not* this file's job.
//! * **Cycle** (the walk runs `> domain_count` steps without reaching a `Root`): a cycle of
//!   length L needs L *distinct* domains, so its witness is **unbounded in domain count** —
//!   §2.4: "there is *no* finite size cutoff for the cycle case." It rests instead on a
//!   **structural induction proving the delegation graph is always a forest** (design-lesson
//!   #13b). That induction, for arbitrary N, is exactly what a model checker cannot do and this
//!   file discharges.
//!
//! ## Why the graph is always a forest — and the coupling that carries it
//!
//! `control_grant` (`hypervisor.rs`) is the only edge-*adding* transition, and it adds an edge
//! only in its **fresh-leaf** case: it records `controls[to][target] = Via(caller)` *only when*
//! `to` did not already control `target` (`Absent`) and `caller` does. If `to` already controls
//! it, `control_grant` is a **no-op that preserves the existing provenance** — it never
//! *re-parents* an existing controller. Re-parenting is the one move that could close a cycle, so
//! forbidding it (idempotent, provenance-preserving) is what buys acyclicity. A graph that only
//! ever grows fresh leaves beneath existing nodes is a forest; a forest has no cycles, at any
//! size. Edge-*removal* (revoke, the teardown cascade) can never create a cycle.
//!
//! ## What is proven, and how the pigeonhole is threaded
//!
//! The honest difficulty (flagged when this residual was picked): *any* faithful proof of the
//! code's exact `steps ≤ n` bound needs a **pigeonhole** — a terminating walk visits distinct
//! nodes, so its length is bounded by the node count. This file threads it with a **rank
//! certificate** (a ghost, not stored state — an inductive-invariant witness):
//!
//! * [`valid_rank`] — a `rank: Seq<nat>` strictly decreasing along every `Via` edge, whose
//!   parent is non-`Absent`. Its existence *is* acyclicity (a cycle would need `rank` to strictly
//!   decrease around a loop).
//! * [`bounded`] — `rank[h] < |non-Absent nodes|`. The fresh-leaf step (`rank[to] :=
//!   rank[caller] + 1`) preserves this **without an explicit pigeonhole**, because
//!   `rank[caller] < count` by the IH and the node count grows by one — the pigeonhole folded
//!   into the invariant.
//! * [`rank_reaches_root`] — a valid rank makes the walk terminate at a `Root` in `rank[h]+1`
//!   fuel (induction on `rank[h]`; self-bounded, no pigeonhole).
//! * [`certificate_discharges_orphaned`] — `valid_rank ∧ bounded ⇒` the walk reaches a `Root`
//!   within `n = col.len()` steps: **exactly `ControlEdgeOrphaned` not firing**, at arbitrary N.
//! * [`control_grant_preserves`] / [`root_stamp_preserves`] — the fresh-leaf delegation and the
//!   `DomainCreate` `Root` stamp both extend the certificate: acyclicity is **inductive**.
//!
//! This is the same *"one property borrows from a relational one"* shape as the earlier Tier C
//! proofs (design-lesson #20/#21): `ControlEdgeOrphaned`'s no-cycle content is carried by the
//! rank certificate, and the fresh-leaf precondition is the load-bearing hypothesis (design-
//! lesson #13b's "never re-parent").
//!
//! ## Fidelity (a mirror, managed)
//!
//! [`Prov`] mirrors `hv_core::hypervisor::Control` (`Absent`/`Root`/`Via(d)`); [`reaches_root`]
//! mirrors the `first_cross_violation` provenance loop (`Root` ok, `Absent` orphan, `> n` steps
//! cycle) with fuel = `col.len()` = `domain_count`; [`control_grant_preserves`]'s preconditions
//! mirror `control_grant`'s fresh-leaf branch (`hypervisor.rs`). The enumerator already checks
//! `ControlEdgeOrphaned` on the *real* `Hypervisor` at small size (Tier A `delegation_cfg`, 4
//! domains — the smallest that forms a `Via`-of-a-`Via`); this adds the ∀-size acyclicity the
//! cycle case needs. See `hv-verify/verus/README.md`.
//!
//! ## Non-vacuity (validated)
//!
//! Weakening the strict rank decrease (`rank[d] < rank[h]` → `≤`) or dropping the fresh-leaf
//! precondition (`is_absent(col[to])`) makes Verus reject the proof — the acyclicity really rests
//! on the strict measure and on never re-parenting (verified by hand; recorded in the README).
//!
//! Run: `verus --crate-type=lib hv-verify/verus/control_forest_acyclic.rs` (exit 0 = all proven).

use vstd::prelude::*;

verus! {

/// Provenance of one control edge in a target's column: `Absent` (no control), `Root` (the
/// creator), or `Via(d)` (domain `d` delegated it). Mirror of `hv_core::hypervisor::Control`.
enum Prov {
    Absent,
    Root,
    Via(int),
}

spec fn is_absent(p: Prov) -> bool {
    matches!(p, Prov::Absent)
}

/// The real `ControlEdgeOrphaned` walk (`first_cross_violation`): follow `Via(d)` up the column
/// until a `Root` (well-formed), an `Absent` (orphan), or `fuel` runs out (cycle). Faithful to
/// the loop with `fuel = n = domain_count`.
spec fn reaches_root(col: Seq<Prov>, h: int, fuel: nat) -> bool
    decreases fuel,
{
    if h < 0 || h >= col.len() {
        false
    } else {
        match col[h] {
            Prov::Root => true,
            Prov::Absent => false,
            Prov::Via(d) => if fuel == 0 {
                false
            } else {
                reaches_root(col, d, (fuel - 1) as nat)
            },
        }
    }
}

/// A rank certificate: strictly decreasing along every `Via` edge, whose parent is non-`Absent`.
/// Its existence **is** acyclicity — a cycle would need `rank` to strictly decrease around a loop.
/// (Ghost: the real code stores no rank; this is the inductive-invariant witness.)
spec fn valid_rank(col: Seq<Prov>, rank: Seq<nat>) -> bool {
    col.len() == rank.len() && forall|h: int| #![trigger col[h]]
        0 <= h < col.len() ==> (match col[h] {
            Prov::Via(d) => 0 <= d < col.len() && !is_absent(col[d]) && rank[d] < rank[h],
            _ => true,
        })
}

/// |non-`Absent` cells| — the number of nodes actually in the target's delegation forest.
spec fn nonabsent_count(col: Seq<Prov>) -> nat
    decreases col.len(),
{
    if col.len() == 0 {
        0
    } else {
        nonabsent_count(col.subrange(0, col.len() - 1)) + (if is_absent(col[col.len() - 1]) {
            0nat
        } else {
            1nat
        })
    }
}

/// Ranks bounded by the node count. This is what folds the pigeonhole into the invariant: a walk
/// of strictly-decreasing ranks all `< node-count` cannot exceed the node count, so it fits the
/// code's `steps ≤ n` budget with no explicit distinct-nodes argument.
spec fn bounded(col: Seq<Prov>, rank: Seq<nat>) -> bool {
    forall|h: int| #![trigger col[h]]
        0 <= h < col.len() ==> (!is_absent(col[h]) ==> rank[h] < nonabsent_count(col))
}

/// The exact code predicate: `ControlEdgeOrphaned` does **not** fire — every non-`Absent` holder's
/// provenance walk reaches a `Root` within `n = col.len()` steps.
spec fn col_ok(col: Seq<Prov>) -> bool {
    forall|h: int| #![trigger col[h]]
        0 <= h < col.len() ==> (!is_absent(col[h]) ==> reaches_root(col, h, col.len()))
}

proof fn count_le_len(col: Seq<Prov>)
    ensures
        nonabsent_count(col) <= col.len(),
    decreases col.len(),
{
    if col.len() > 0 {
        count_le_len(col.subrange(0, col.len() - 1));
    }
}

/// The heart of acyclicity: a valid rank makes the provenance walk **terminate at a `Root`** —
/// within `rank[h] + 1` fuel (self-bounded, no pigeonhole). Induction on `rank[h]`: a `Via` step
/// goes to a strictly smaller rank whose parent is non-`Absent`, so the IH applies.
proof fn rank_reaches_root(col: Seq<Prov>, rank: Seq<nat>, h: int, fuel: nat)
    requires
        valid_rank(col, rank),
        0 <= h < col.len(),
        !is_absent(col[h]),
        fuel > rank[h],
    ensures
        reaches_root(col, h, fuel),
    decreases rank[h],
{
    if let Prov::Via(d) = col[h] {
        rank_reaches_root(col, rank, d, (fuel - 1) as nat);
    }
}

/// The acyclicity certificate discharges the real `ControlEdgeOrphaned` check, at **arbitrary
/// size**: a valid, bounded rank ⇒ no orphan and no cycle, within the code's `n`-step budget.
proof fn certificate_discharges_orphaned(col: Seq<Prov>, rank: Seq<nat>)
    requires
        valid_rank(col, rank),
        bounded(col, rank),
    ensures
        col_ok(col),
{
    count_le_len(col);
    assert forall|h: int| #![trigger col[h]]
        0 <= h < col.len() && !is_absent(col[h]) implies reaches_root(col, h, col.len()) by {
        // rank[h] < nonabsent_count(col) <= col.len(), so col.len() > rank[h].
        rank_reaches_root(col, rank, h, col.len());
    }
}

/// Flipping one `Absent` cell to a present one raises the node count by exactly 1.
proof fn count_flip_absent_to_present(col: Seq<Prov>, i: int, p: Prov)
    requires
        0 <= i < col.len(),
        is_absent(col[i]),
        !is_absent(p),
    ensures
        nonabsent_count(col.update(i, p)) == nonabsent_count(col) + 1,
    decreases col.len(),
{
    let col2 = col.update(i, p);
    let last = col.len() - 1;
    if i == last {
        assert(col2.subrange(0, last) =~= col.subrange(0, last));
    } else {
        assert(col2.subrange(0, last) =~= col.subrange(0, last).update(i, p));
        count_flip_absent_to_present(col.subrange(0, last), i, p);
    }
}

/// **PRESERVATION — the crux.** `control_grant`'s fresh-leaf case (`hypervisor.rs`): `to` did not
/// control `target` (`col[to]` `Absent`) and `caller` does (`col[caller]` non-`Absent`); record
/// `col[to] = Via(caller)`. Extending the certificate with `rank[to] = rank[caller] + 1` keeps it
/// valid **and** bounded — so acyclicity is inductive, at arbitrary domain count. This is the
/// residual Tier B §2.4 could not reach by enumeration (the cycle case has no size cutoff).
proof fn control_grant_preserves(col: Seq<Prov>, rank: Seq<nat>, caller: int, to: int)
    requires
        valid_rank(col, rank),
        bounded(col, rank),
        0 <= caller < col.len(),
        0 <= to < col.len(),
        !is_absent(col[caller]),  // caller controls target (the authority precondition)
        is_absent(col[to]),       // to is a FRESH leaf (the non-idempotent branch)
    ensures
        ({
            let col2 = col.update(to, Prov::Via(caller));
            let rank2 = rank.update(to, (rank[caller] + 1) as nat);
            valid_rank(col2, rank2) && bounded(col2, rank2)
        }),
{
    let col2 = col.update(to, Prov::Via(caller));
    let rank2 = rank.update(to, (rank[caller] + 1) as nat);
    // caller != to (col[caller] non-Absent, col[to] Absent), so caller's cell and rank are
    // untouched — that is what makes the extension consistent.
    assert(caller != to);
    count_flip_absent_to_present(col, to, Prov::Via(caller));
    assert(valid_rank(col2, rank2)) by {
        assert forall|h: int| #![trigger col2[h]]
            0 <= h < col2.len() implies (match col2[h] {
            Prov::Via(d) => 0 <= d < col2.len() && !is_absent(col2[d]) && rank2[d] < rank2[h],
            _ => true,
        }) by {
            if h == to {
                // col2[to] == Via(caller): caller in range; col2[caller] == col[caller]
                // non-Absent; rank2[caller] == rank[caller] < rank[caller] + 1 == rank2[to].
                assert(col2[caller] == col[caller]);
            } else {
                assert(col2[h] == col[h]);
                if let Prov::Via(d) = col2[h] {
                    // valid_rank(col): col[d] non-Absent, so d != to (col[to] Absent) — untouched.
                    assert(col2[d] == col[d]);
                }
            }
        }
    }
    assert(bounded(col2, rank2)) by {
        assert forall|h: int| #![trigger col2[h]]
            0 <= h < col2.len() && !is_absent(col2[h]) implies rank2[h] < nonabsent_count(
            col2,
        ) by {
            if h != to {
                assert(col2[h] == col[h]);
            }
        }
    }
}

/// `DomainCreate` stamps `controls[creator][newtarget] = Root` (`hypervisor.rs`) — a fresh node
/// with rank 0 and no outgoing `Via`, the base of the forest. It too extends the certificate.
proof fn root_stamp_preserves(col: Seq<Prov>, rank: Seq<nat>, c: int)
    requires
        valid_rank(col, rank),
        bounded(col, rank),
        0 <= c < col.len(),
        is_absent(col[c]),
    ensures
        ({
            let col2 = col.update(c, Prov::Root);
            let rank2 = rank.update(c, 0nat);
            valid_rank(col2, rank2) && bounded(col2, rank2)
        }),
{
    let col2 = col.update(c, Prov::Root);
    let rank2 = rank.update(c, 0nat);
    count_flip_absent_to_present(col, c, Prov::Root);
    assert(valid_rank(col2, rank2)) by {
        assert forall|h: int| #![trigger col2[h]]
            0 <= h < col2.len() implies (match col2[h] {
            Prov::Via(d) => 0 <= d < col2.len() && !is_absent(col2[d]) && rank2[d] < rank2[h],
            _ => true,
        }) by {
            if h != c {
                assert(col2[h] == col[h]);
                if let Prov::Via(d) = col2[h] {
                    assert(col2[d] == col[d]);
                }
            }
        }
    }
    assert(bounded(col2, rank2)) by {
        assert forall|h: int| #![trigger col2[h]]
            0 <= h < col2.len() && !is_absent(col2[h]) implies rank2[h] < nonabsent_count(
            col2,
        ) by {
            if h != c {
                assert(col2[h] == col[h]);
            }
        }
    }
}

} // verus!
