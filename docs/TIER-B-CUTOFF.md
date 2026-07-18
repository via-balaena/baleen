<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Tier B — the cutoff / small-scope-completeness argument

*Status: analysis + instrumentation landed. This is a reasoning artifact, not a machine
proof — it says exactly what the bounded model checking already proves at all sizes and all
depths, and exactly what it does not (which is Tier C's job). Read alongside
`hv-sim/src/enumerate.rs` (the checker this argument is about) and the `first_violation` /
`first_cross_violation` methods in `hv-core` (the 28 invariants it reasons over).*

## 0. What Tier B is, and is not

Everything verified so far is **bounded model checking**: `hv-sim::enumerate` breadth-first
visits *every* reachable state of a **tiny fixed configuration** (2–4 domains, 2–4 frames,
2 ports, 1–2 vCPUs, 1–2 pCPUs, 2 grants) out to a **bounded hypercall depth**, and checks
the integrated invariant at each. Where a random walk says "no seed hit a violation," this
says "no state reachable within *these bounds* can." That is extraordinarily strong
*evidence*, but its scope is finite along two independent axes:

- **Depth** — the number of hypercalls from `new()`. A depth-7 sweep says nothing *directly*
  about a system that has run for 8 hypercalls, or 8 million.
- **Size** — the number of domains / frames / ports / vCPUs / pCPUs / grants. A 3-domain
  sweep says nothing *directly* about a 300-domain system.

**Tier B is the argument that small-and-shallow exhaustiveness generalizes to all sizes and
all depths** — turning "exhaustive over tiny" into "exhaustive, period." It is *not* the
deductive preservation proof (that every transition preserves every invariant for arbitrary
size — Tier C) and *not* non-interference (that the invariants collectively imply real
isolation — Tier D). Its honest yield is two things: a **real theorem** it establishes
outright (the depth axis, for most configs, via *saturation*), and a **precise map** of the
handful of residual obligations it *cannot* discharge by enumeration and therefore hands to
Tier C. The value of a cutoff argument is as much in the wall it finds as in the ground it
clears.

---

## 1. The DEPTH axis — saturation

### 1.1 The key distinction the enumerator did not used to make

The BFS loop in `enumerate()` ends in one of three ways:

1. **Truncation** — it hit the `max_states` safety cap. A *lower bound*: "these N states are
   all safe," nothing about the rest.
2. **Depth exhaustion** — it ran the full `cfg.depth` rounds with states *still on the
   frontier*. Complete **up to** that depth; there are provably more states deeper.
3. **Saturation** — the frontier went **empty** before the depth budget ran out. Every
   reachable state has been visited **at every depth**. This is an **all-depths theorem**
   for that fixed configuration: the depth bound has dissolved.

Until this arc the code conflated (2) and (3): both reported "closed — complete for this
depth." A run that had explored 5.66M states without truncating *looked* done, but the
enumerator never recorded whether the frontier had actually emptied. `EnumOutcome` now
carries a `saturated: bool`, set true only when the frontier empties **without** any
truncation (a capped run cannot prove a frontier empty). The distinction is one branch in
the BFS loop — but it changes the *kind* of guarantee a closed run yields.

### 1.2 Why saturation is reachable at all — finiteness

Saturation can only happen if the config's reachable state set is **finite**. It is finite
iff `state_key` (the BFS dedup fingerprint) carries no unbounded field. Auditing every
component of `state_key`:

| field | range | bounded by |
|---|---|---|
| port state tag / remote / remote_port | 5 tags × D domains × P ports | config sizes |
| port pending / masked | {0,1} | — |
| vCPU run-state tag / pcpu | 4 tags × C pcpus | config sizes |
| vCPU affinity mask | 2^C | pCPU count |
| pCPU occupancy | D×V + 1 | config sizes |
| frame owner / type tag / pinned | D × 6 × {0,1} | config sizes |
| page-table edge set `(parent,slot,child,writable,leaf)` | ≤ (F×2) edges | frames × 2 slots |
| domain liveness / may_create | {0,1} | — |
| control matrix cell `Absent/Root/Via(d)` | D+2 per cell, D² cells | domain count |
| **grant `maps` / `writable_maps`** | **0 .. u32::MAX** | **⚠ nothing** |
| **frame `refs` / `writable_refs` / `pagetable_refs`** | **0 .. u32::MAX** | **⚠ nothing** |

Every field is bounded by a config size **except the refcounts**. `grant::map` bumps `maps`
with a `checked_add(1)` and **no per-grant cap** (`hv-core/src/grant.rs:253`); a domain may
map an owned frame arbitrarily many times, each map a distinct `state_key`. So:

- A config with **no way to grow a refcount** has a finite reachable set and **must saturate**
  at some depth (BFS cannot forever enqueue new states from a finite set).
- A config that **can** grow a refcount without bound has an **infinite** reachable set and
  **can never saturate** — it is finite only *per depth bound*.

A refcount grows only when a reference is *taken*: a grant map backing an **owned** frame, or
a page-table pin/link. All frames boot `Free` (`p2m.rs:317`), so a grant map cannot back
anything until some frame is `P2mAllocate`d and owned. Pins are idempotent (`pin` refuses an
already-pinned frame, `p2m.rs:495`) and links are capped at one per `(parent,slot)`, so the
page-table references are bounded by `frames × 2`. **The one genuinely unbounded generator is
a grant map over an owned frame — i.e. `grant` and `p2m` enabled *together*.**

### 1.3 What actually saturates — the measured table

Running each seam config with the new instrumentation (see
`hv-sim/examples/saturation_probe.rs`, a scratch harness):

| config | subsystems | saturation depth | states | verdict |
|---|---|---:|---:|---|
| grant-only (+create/destroy) | grant | 8 | 26,345 | **SATURATES** — maps can't back (no owned frame) |
| event-channels only | evtchn | 16 | 171,145 | **SATURATES** |
| vCPU affinity | sched | 16 | 237,312 | **SATURATES** (asserted by `vcpu_affinity_deep`) |
| domain lifecycle | p2m+create+destroy+delegate | 16 | 47,496 | **SATURATES** (asserted by `domain_lifecycle_deep`) |
| delegation forest (4 dom) | create+destroy+delegate | 12 | 58,280 | **SATURATES** (asserted by `delegation_forest_deep`) |
| domain-ID reuse | evtchn+grant (no p2m) | — | — | **finite → saturates** (§1.2: no owned frame ⇒ no unbounded refcount; deep, not run to an empty frontier here) |
| authority × seams (3 dom) | evtchn+grant+delegate | — | — | **finite → saturates** (§1.2: no p2m; large 3-domain space) |
| four-level hierarchy | p2m (L1–L4, 4 frames) | — | — | **finite → saturates** (§1.2: pins idempotent, links capped ⇒ refs bounded; large) |
| event ↔ scheduler | evtchn+sched | — | — | **finite → saturates** (§1.2: both subsystems bounded; large — >6M states) |
| **grant ↔ p2m** | **grant+p2m** | **never** | ∞ | **UNBOUNDED** — `maps`/`refs` climb per map |

The five top rows are run **to an empty frontier** — a measured all-depths theorem; the three
affinity/lifecycle/delegation ones are now asserted in-tree by the `*_deep` tests
(`expect_saturated`, which fails unless the frontier empties). The four middle rows are proven
*finite* by §1.2 (they contain no refcount that can grow without bound) and therefore *must*
saturate at some depth — but their reachable sets are large enough that emptying the frontier
is expensive, so they are marked as reasoned, not yet run to saturation on this machine. Only
the last row is genuinely infinite.

The grant↔p2m growth is monotone and explosive — 1.3k (d3) → 9.9k (d4) → 51k (d5) → 211k
(d6) → 828k (d7) → truncates — and the direct witness is unambiguous: allocate a frame, grant
it, map it ten times, and each map is a fresh distinct state with no cap in sight
(`saturation_probe.rs`, final block).

**The headline:** the majority of the verification surface — every config whose state cannot
grow a refcount — was already an all-depths theorem; it simply had never been *recognized* as
one because the enumerator never distinguished an empty frontier from an exhausted budget. The
depth axis is **closed** for those configs, outright, by running them to saturation. This is
the "big, clean simplification" Tier B was hoped to open with, and it holds — for everything
except the grant↔p2m refcount.

### 1.4 The unbounded frontier — where enumeration provably cannot reach, and why it's benign

For grant↔p2m no depth suffices: the reachable set is genuinely infinite. But the
unboundedness is **confined to monotone counters that no invariant can exploit.** Every
refcount-bearing invariant is an *inductive inequality or equality that every transition
preserves in lockstep*, independent of magnitude:

- `RefcountMismatch` (grant): `maps == |live mappings of this grant|` — `map` bumps both sides,
  `unmap` drops both.
- `WritableExceedsMaps` / `ReadonlyViolated` (grant): `writable_maps ≤ maps`, `readonly ⇒
  writable_maps == 0` — every map respects both.
- `TypedExceedsRefs` / `TypeConfusion` (p2m): `writable_refs + pagetable_refs ≤ refs`,
  `¬(writable_refs>0 ∧ pagetable_refs>0)` — every reference-take bumps `refs` too.
- `UnbackedGrantMap` (cross): `refs(frame) ≥ Σ maps over frame` — a grant map bumps `refs` by
  at least the maps it adds.

A state with `maps == 100` is, for the purpose of these predicates, indistinguishable from
`maps == 2`: the relation holds or fails identically. So a counterexample, if one existed,
would **already appear at the smallest refcount that sets up the relation** — which the
depth-7 grant↔p2m sweep (refcounts 0..7, 828k states, zero violations) covers with margin.

Making this a *theorem* rather than strong evidence is a **counter abstraction**: quotient
each refcount at a small cap K (values ≥K collapse to "K+"), prove the abstract transition
system *simulates* the concrete one, and enumerate the now-finite abstraction. That soundness
obligation — the abstraction introduces no spurious safety and the invariants are insensitive
to counter values above K — is an **inductive preservation proof**, which is **Tier C's
domain, not enumeration's.** This is the precise point where deductive verification stops being
optional: *you cannot enumerate an infinite space*, and the infinity is exactly the refcounts.
Tier B's contribution here is to have located that boundary exactly and shown that everything
on the near side of it is already closed.

---

## 2. The SIZE axis — symmetry, locality, projection

The depth axis, closed by saturation, still only covers *fixed* small sizes. The size axis
asks: does a clean run at K domains/frames/… imply safety at all N? The argument has three
parts: symmetry (only sizes matter, not identities), locality (each invariant's witness is
small — a *cutoff* size k0), and projection (a violation at any N implies one at ≤ k0).

### 2.1 Data-independence / symmetry — only sizes matter, not identities

**Claim.** No transition and no invariant branches on the *specific value* of any domain,
frame, port, vCPU, or pCPU id; ids are compared only by equality and by stored relationship
(grantor==owner, a port's `remote`, a link's `parent`/`child`, a control cell's `Via(d)`).

**Evidence.** A sweep of `hv-core` for literal id constants finds exactly **one** asymmetry,
both occurrences in `Hypervisor::new`: domain 0 boots `Live` with `may_create`, every other
slot boots `Dead` without it (`hypervisor.rs:514,520`). Nothing else in the core — no
transition, no `first_violation`, no `first_cross_violation` — contains a `dom == k` literal.
The 28 invariants read ids only structurally (indices into vectors, equality tests, reciprocity
lookups).

**Consequence.** The initial state is invariant under any permutation of ids that fixes the
sole distinguished element, domain 0. Formally the symmetry group is
`S_frames × S_ports × S_vcpus × S_pcpus × S_grants × Stab₀(S_domains)` (the stabilizer of dom0
over domains, full symmetry over everything else), and the transition relation and invariant
set are equivariant under it. Therefore a reachable violating state at *any* id-assignment has
an isomorphic reachable violating state at the **canonical** assignment `{0, 1, …, k−1}`. **The
identities are irrelevant; only the multiplicities (sizes) matter.** This is the standard
data-independence reduction, and here it is exact because the code is, by construction,
id-agnostic except at boot.

### 2.2 Per-invariant locality → a size cutoff k0

**Claim.** Each invariant is *local*: it is violated by a **bounded** set of entities (its
*witness*), independent of the total system size. The largest witness across all invariants
gives a cutoff k0 — a violation cannot *need* more than k0 of each entity kind.

Walking all 28 invariants (subsystem `first_violation` + the nine cross-checks), with the
witness entity-set and the domains/frames/… it spans:

| invariant | witness | doms | frames | ports | vcpus | pcpus | grants |
|---|---|---:|---:|---:|---:|---:|---:|
| evtchn `FreePortHasSignal` | 1 port | 1 | – | 1 | – | – | – |
| evtchn `ReciprocityBroken` | a port + its named peer | 2 | – | 2 | – | – | – |
| evtchn `UnboundGhostDomain` | 1 port (range check) | 1 | – | 1 | – | – | – |
| evtchn `DuplicateVirq` | 2 ports, same domain | 1 | – | 2 | 1 | – | – |
| grant `GranteeGhostDomain` | 1 entry (range check) | 1 | – | – | – | – | 1 |
| grant `WritableExceedsMaps` | 1 entry | 1 | – | – | – | – | 1 |
| grant `ReadonlyViolated` | 1 entry | 1 | – | – | – | – | 1 |
| grant `RefcountMismatch` | 1 entry + its mappings | 2 | – | – | – | – | 1 |
| grant `DanglingMap` | 1 mapping + its entry | 2 | – | – | – | – | 1 |
| sched `RunningGhostPcpu` | 1 vCPU (range check) | 1 | – | – | 1 | 1 | – |
| sched `OccupancyBroken` | 1 vCPU + 1 pCPU | 1 | – | – | 1 | 1 | – |
| sched `RunningOffAffinity` | 1 vCPU + mask + 1 pCPU | 1 | – | – | 1 | 2 | – |
| sched `OccupantGhost` | 1 pCPU (range check) | 1 | – | – | 1 | 1 | – |
| sched `OccupantNotRunning` | 1 pCPU + 1 vCPU | 1 | – | – | 1 | 1 | – |
| p2m `OwnerGhostDomain` | 1 frame (range check) | 1 | 1 | – | – | – | – |
| p2m `TypeConfusion` | 1 frame | 1 | 1 | – | – | – | – |
| p2m `TypedExceedsRefs` | 1 frame | 1 | 1 | – | – | – | – |
| p2m `PinnedNotPageTyped` | 1 frame | 1 | 1 | – | – | – | – |
| p2m `MislevelledLink` | 1 edge (parent+child) | 1 | 2 | – | – | – | – |
| cross `MisownedGrantMap` | 1 grant + 1 frame | 1 | 1 | – | – | – | 1 |
| cross `UnbackedGrantMap` | 1 frame + its grants | 1 | 1 | – | – | – | ≤G |
| cross `LostWakeup` | 1 port + notify vCPU | 1 | – | 1 | 1 | – | – |
| cross `UnauthorizedForeignLink` | 1 edge + 2 owners + 1 grant | 2 | 2 | – | – | – | 1 |
| cross `DeadDomainNotClean` | 1 dead dom + 1 resource | 1 | ≤1 | ≤1 | ≤1 | – | ≤1 |
| cross `DeadDomainReferenced` | 1 dead dom + 1 referrer | 2 | – | ≤1 | – | – | ≤1 |
| cross `DeadDomainMayCreate` | 1 dom | 1 | – | – | – | – | – |
| cross `ControlEdgeDeadEndpoint` | 1 edge (2 doms) | 2 | – | – | – | – | – |
| cross `ControlEdgeOrphaned` (orphan) | edge + delegator cell | 3 | – | – | – | – | – |
| cross `ControlEdgeOrphaned` (**cycle**) | a provenance cycle | **≤D** ⚠ | – | – | – | – | – |

**27 of the 28 are local.** The witness counts above are the entities the invariant *reads*;
the cutoff also has to account for the entities needed to *reach* that witness from the uniform
initial state — and because every non-dom0 slot boots `Dead` (§2.1), a domain only becomes live
by being created, ultimately rooted at dom0. So a witness on *m* live non-dom0 domains needs up
to *m*+1 domains in the config (dom0 as the creating Root). Two invariant families set the
domain bound:

- **memory / sharing** (`UnauthorizedForeignLink`, `MisownedGrantMap`, the grant/p2m seams):
  witness ≤ 2 owners; with dom0 possibly a third distinct party (A grants to B while C also
  owns/maps), **3 domains** — exactly `grant_p2m_3dom_cfg`.
- **authority chains** (`ControlEdgeOrphaned` orphan, `ControlEdgeDeadEndpoint`, delegation):
  the orphan witness is 3 domains (holder, delegator, target), and reaching it needs a Root
  creator behind the chain — dom0 plus a depth-2 delegation chain = **4 domains** — exactly
  `delegation_cfg` (4), the smallest world that can even *form* a `Via`-of-a-`Via`.

Taking the max over all families gives the cutoff

> **k0 = (4 domains, 3 frames, 2 ports, 2 vCPUs, 2 pCPUs, 2 grants).**

Note what this means for **Tier A**: its 3-domain grant/p2m sweep (`grant_p2m_3dom_cfg`) and
4-domain delegation sweep (`delegation_cfg` / `authority_seams_cfg`) were not "just a bigger K
for reassurance" — *together* they are, in retrospect, exactly the **base case of the cutoff**:
a clean exhaustive run at k0 for each family that needs it. The size axis reduces to "does k0
hold?", and Tier A checked k0.

### 2.3 The projection lemma — the honest gap, stated precisely

Symmetry (§2.1) plus locality (§2.2) give the cutoff *only* through a **projection lemma**:

> If config N has a reachable state s violating a local invariant I with witness W (|W| ≤ k0),
> then the sub-config on W's entities (size ≤ k0) has a reachable state s′ that also violates I.

The construction is standard: take the hypercall trace σ reaching s, keep the subsequence that
touches W's entities (and their causal predecessors), remap the ids into `0..k0` (legal by
§2.1), and argue the projected trace is valid in the small config and reaches a state agreeing
with s on W. Its soundness rests on a **frame property**: a transition on entities disjoint
from W does not perturb W's projected state. Reviewing the transition classes, this holds at
the granularity the invariants observe —

- Slot-reuse (`alloc_handle`, `alloc_link`, mapping/link vectors) shifts *indices*, but no
  invariant reads an index; they read *contents* (`grantor,gref,grantee`; `parent,slot,child`),
  which are index-independent.
- `maps_over_frame` (the one summation) ranges over grants naming **one** frame, and only the
  frame's **owner** can have live maps over it (`MisownedGrantMap` fires otherwise), so an
  unrelated domain contributes nothing — the sum is owner-local.
- `any_grant_to` / `any_unbound_into` (`DeadDomainReferenced`) scan for **one** referrer of the
  dead slot; the witness is that referrer.

— but a *machine-checked* frame lemma (every transition's write-set is disjoint from every
other entity's invariant read-set) is itself a **deductive obligation, Tier C-grade**. Tier B
states the lemma, justifies it per transition class, and marks it as the load-bearing step the
size cutoff imports. It is not hand-waved into a theorem here.

### 2.4 The control-cycle wrinkle — a genuinely non-local invariant

`ControlEdgeOrphaned` splits into two cases with different character:

- **Orphan** (a `Via(d)` edge whose delegator cell `controls[d][target]` is `Absent`): local,
  witness = 3 domains. Covered by the cutoff.
- **Cycle** (the provenance walk visits more than `domain_count` cells without reaching a
  `Root`): **non-local** — a cycle of length L needs L *distinct* domains, so its witness is
  **unbounded in domain count.** There is *no* finite size cutoff for the cycle case.

This is a real limitation of the cutoff method, honestly flagged. It does not mean a cycle is
reachable — it means the *no-cycle* fact cannot be obtained by "check up to k0." It rests
instead on a **structural, by-construction argument** (design-lesson #13b): a `Via` edge only
ever attaches a *fresh leaf* — a domain that did not already control the target — beneath an
existing delegator, and `ControlGrant` is idempotent and provenance-preserving (it never
re-parents an existing controller). A graph that only ever grows fresh leaves is a **forest**;
a forest has no cycles, at any size. That is a structural induction over the delegation graph,
**not** a size cutoff — again squarely in Tier C's territory (an inductive invariant on the
transition relation, proven for arbitrary N).

---

## 3. Honest ledger — what Tier B closes, what it hands to Tier C

**Closed by Tier B, outright:**

- **The depth axis for every bounded-state config** — a *theorem*, via saturation, now
  machine-checkable by running to an empty frontier (the `saturated` flag). Most of the
  verification surface (evtchn, sched/affinity, lifecycle, delegation, and the grant/authority
  configs that lack an owned frame to map) is proven safe **at all depths**, not merely up to a
  bound. This was latent in the existing sweeps and is now made explicit.
- **Symmetry** — the reduction from "all id-assignments" to "canonical `0..k−1`" is exact,
  because the code is id-agnostic except for dom0 at boot.
- **The per-invariant locality analysis and the cutoff k0** — 27 of 28 invariants have a
  bounded witness; k0 = (4,3,2,2,2,2); Tier A's 3-domain grant/p2m + 4-domain delegation
  sweeps are its combined base case.

**Handed to Tier C (deductive), because enumeration provably cannot reach it:**

1. **The refcount-unbounded configs (grant↔p2m)** — infinite state space; needs a counter
   abstraction whose soundness is an inductive-preservation proof. The invariants involved are
   already-identified inductive inequalities, so this is well-posed.
2. **The projection frame-lemma** — the size cutoff imports it; a machine-checked version is a
   per-transition disjointness proof.
3. **The control-cycle acyclicity** — a structural induction over the delegation forest, not a
   size cutoff.

All three residuals are **deductive, not enumerative** — they quantify over *all* states, which
is exactly what Tier C (Verus / Kani / Lean) does and what a model checker cannot. Tier B's
lasting result is therefore twofold: it *proves* the depth generalization for the bounded
majority, and it *pins down* the exact, finite list of obligations that force the move to
deductive proof. The bounded→unbounded frontier is no longer a vague "we only checked small
things"; it is this ledger.

---

*Instrumentation: `EnumOutcome.saturated` in `hv-sim/src/enumerate.rs`; the
`expect_saturated` test helper; and the saturating deep sweeps now assert an empty frontier
(an all-depths theorem) rather than mere non-truncation. Scratch measurement harnesses live in
`hv-sim/examples/saturation_probe.rs`.*
