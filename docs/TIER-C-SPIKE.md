<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Tier C — the deductive spike (Kani bridge → Verus)

*Status: tooling decided, repo/CI shape landed, Kani bridge green, and **all three §3 residuals
discharged in Verus** — `RefcountMismatch` over arbitrary table size (§4), the projection
frame-lemma / grant-summation owner-locality (§5), and the control-forest acyclicity / cycle case
(§6). The Verus phase's stated obligation list is complete; what remains of true-diamond is Tier
D (non-interference). These are ∀-N proofs of the *model* (the pure brain); the metal is M3+. Read
alongside `hv-verify/src/lib.rs` (the harnesses), `hv-core/src/grant.rs` (the code they prove
over), and `docs/TIER-B-CUTOFF.md` §3 (the three residuals Tier C inherits).*

## 0. What Tier C is

Everything through Tier B is **bounded model checking**: `hv-sim::enumerate` visits every
reachable state of a *small* config, and Tier B's cutoff/saturation argument generalizes the
*depth* axis to all depths for every bounded-state config. What it provably **cannot** reach
(`docs/TIER-B-CUTOFF.md` §3) are three obligations that quantify over *all* states rather than
enumerate small ones:

1. **The refcount-unbounded configs (grant↔p2m)** — `grant::map` bumps `maps: u32` with no
   cap, so the reachable set is genuinely *infinite* along the counter axis; no enumeration
   closes it. Needs an inductive preservation proof.
2. **The projection frame-lemma** (§2.3) — a per-transition write-set ⟂ read-set disjointness
   proof that the size cutoff imports.
3. **The control-cycle acyclicity** (§2.4) — a structural induction over the delegation forest.

All three share one shape — **inductive preservation**, `∀ s. INV(s) ⇒ ∀ t. INV(t(s))`, for
arbitrary size. That universal quantifier over states *is* Tier C; it is what a deductive tool
does and a model checker cannot. This is the qualitative jump that makes the brain "truly"
diamonded (seL4-in-Isabelle / CertiKOS-in-Coq tier) — for the *model*; whether the *metal*
enforces the model is M3+, outside this program.

## 1. The tooling decision — Kani bridge, then Verus

Assessed against *this* codebase: real Rust, `no_std`, `unsafe` forbidden workspace-wide,
invariants already written as executable `first_violation` predicates, obligations that are
one-step preservation.

- **Kani** (AWS) symbolically executes the **real** hv-core code. A scalar made
  `kani::any::<u32>()` is proven over *all* 2³² values by its SMT backend — with **no
  unwinding**, because a counter is not a collection. So for residual #1's *magnitude*, Kani
  delivers a genuinely **unbounded** proof — the exact dimension Tier B could not enumerate.
  It stays bounded only along the `Vec`-length axis (entries / live mappings need an `unwind`
  bound). Near-zero rewriting; reuses the production transitions and predicates as-is.
- **Verus** (SMT, Z3) proves `∀`-quantified properties including over arbitrary `Vec` lengths
  — the **full ∀-N** result — but in its own dialect: the transitions and predicate must be
  *ported* into the Verus subset. That port is the person-weeks cost.
- **Lean 4 / Coq** (extract the machine, prove in the prover) is heaviest and carries a
  model-fidelity gap the other two avoid; reserved for Tier D non-interference if wanted.

**Decision (with the user, at the reserved fork): Kani first as a low-friction bridge, then
Verus for the ∀-N program.** The dominant risk at the start is not "which tool is strongest"
but "does deductive verification on *this* code pay off at a tolerable effort-per-obligation?"
Kani answers that against the real code cheaply, *and* closes the specific infinity Tier B
flagged. Verus then lifts the same obligations to arbitrary size once the proof shape is known.

## 2. Repo & CI shape

- **`hv-verify`** — a new **workspace member** holding the proofs. Its harnesses are
  `#[cfg(kani)]`-gated, so under a normal `cargo build` / `cargo test --workspace` it compiles
  to a trivially-empty library with only the internal `hv-core` path dep. `kani` is **not** a
  declared dependency (the `cargo kani` driver injects it), so the shipping dependency graph,
  MSRV, clippy, and cargo-deny are all untouched. Kani runs out-of-band: `cargo kani -p
  hv-verify`.
- **In-tree, not a fork** — a preservation proof is only valuable if it tracks the *current*
  transition code; a fork drifts. Kani harnesses the real public API, so nothing is mirrored
  or re-modelled (the Verus phase, being a dialect, will need a small mirror in `hv-verify`,
  cross-checked against the enumerator to manage fidelity — a decision flagged for when we
  reach it, not made here).
- **CI** — the proofs run in the scheduled `Deep verification` workflow (weekly + dispatch),
  **not** the per-PR required checks: installing Kani + its CBMC backend costs minutes, and the
  proofs are continuous verification, the same class as the exhaustive enumerator sweeps. Kani
  is version-pinned (`kani-verifier@0.67.0`), mirroring the cargo-deny pin, so a release cannot
  silently change proof semantics.
- **The MSRV wrinkle, resolved honestly** — Kani ships a pinned nightly (currently 1.93) below
  the workspace MSRV (1.96), and forwards no `--ignore-rust-version` escape, so a `rust-version`
  *manifest gate* would make cargo refuse to build the libraries for the proof. MSRV is
  therefore enforced by the `MSRV (1.96)` **CI job** (a `cargo check` on the floor — the real,
  single-source guard) and the redundant manifest gate is omitted, with the rationale recorded
  in `Cargo.toml`. Restore the manifest `rust-version` once Kani's toolchain reaches the floor.

## 3. What the spike proves — and the finding it surfaced

The spike targets the cleanest residual: the grant refcount invariant **`WritableExceedsMaps`**
(`writable_maps ≤ maps`). To keep the proof faithful, the count arithmetic of `map`/`unmap` was
factored into `System::counts_after_map` / `counts_after_unmap` — **one** definition the
production transitions *and* the proofs call (design-lesson #14c, no drift). Four harnesses,
all green:

| harness | proves |
|---|---|
| `writable_exceeds_maps_preserved_under_map` | `WritableExceedsMaps` survives a map for **all** magnitudes; the unchecked `writable_maps + 1` **cannot overflow** given the invariant |
| `writable_exceeds_maps_preserved_under_unmap` | survives an unmap of a live mapping, for all magnitudes |
| `map_then_unmap_restores_counts` | the ±1 lockstep is **exact** (map then unmap restores the counts) — the scalar heart of `RefcountMismatch` |
| `real_map_preserves_first_violation_bounded` | the *real* `System::map` leaves `first_violation()` `None` (bounded on table size — demonstrates the bridge reaches the full state machine) |

**The finding (this is the spike earning its keep).** `WritableExceedsMaps` is **not
self-inductive under unmap.** With `writable = false`, `maps = 5`, `writable_maps = 5` the
invariant holds before yet fails after (`maps` drops to 4, `writable_maps` stays 5) — Kani
produced exactly that counterexample when the harness assumed only `writable_maps ≤ maps`. The
missing hypotheses are consequences of **`RefcountMismatch`** on the actual mapping being
released (a live mapping is removed, so `maps ≥ 1`; a read-only unmap removes one of the `maps`
that is not among the `writable_maps`, so `writable_maps ≤ maps − 1`). Under those
reachable-state facts the invariant survives at every magnitude.

So the "±1 lockstep, insensitive to magnitude" that Tier B §1.4 described is, precisely, a
**coupling**: `WritableExceedsMaps`'s inductiveness *borrows* from `RefcountMismatch`. You
cannot prove the scalar inequality preserved in isolation — the relational invariant carries
it. This is exactly the precision Tier C adds over Tier B's prose, and it pins the next
obligation.

## 4. The Verus phase — `RefcountMismatch`, ∀ table size (LANDED)

`RefcountMismatch` (`maps == |live mappings|`, `writable_maps == |writable live mappings|`)
couples a scalar to a `Vec` length — proving *it* preserved is the arbitrary-size step Kani
would have to `unwind`, and was the natural first **Verus** obligation. It is now proven:
`hv-verify/verus/refcount_mismatch.rs` verifies (Verus `0.2026.07.12`, green) that
`RefcountMismatch` is preserved by grant `map` **and** `unmap` over an **arbitrary entry table
× arbitrary-length mapping sequence** — the genuine ∀-N result, not a bounded one. With it in
hand the unmap coupling of §3 closes for arbitrary size, not merely as an assumed precondition:
the two facts the Kani harness had to `assume` (`maps ≥ 1`; read-only ⇒ `writable_maps ≤
maps−1`) are exactly the consequences of `RefcountMismatch` the Verus `count_positive` /
`count_update` lemmas now supply.

**Fidelity — a mirror, managed.** Verus is a dialect (`spec fn`/`requires`/`ensures` do not
parse under stable `rustc`, and Verus front-ends the whole crate it verifies), so unlike the
Kani harnesses — ordinary Rust, `#[cfg(kani)]`-hidden, pointing at real code — the Verus proof
cannot verify `hv-core` in place without breaking the shipping build. So it is a **mirror**,
kept in `hv-verify/verus/` (outside `src/`, so cargo never compiles it), with fidelity to the
shipped transition managed three ways (documented in `hv-verify/verus/README.md`): the mirror's
`counts_after_map`/`counts_after_unmap` transcribe the production functions expression-for-
expression (#14c); its `matches`/`count` mirror `first_violation`'s filter; and the enumerator
already pins fidelity on the *real* code at small size (Kani on the magnitude axis) — Verus adds
the length axis. **Non-vacuity** is validated the enumerator's way: perturbing the arithmetic
(drop the `+1`, drop the writable bump, drop the decrement) makes Verus reject the proof.

**Effort finding (honest, for the "person-months, research-grade" caveat).** This keystone
obligation was *not* a heavy lift: the proof is ~7 lemmas/theorems and went green in three
scratch iterations with only textbook `Seq` induction + extensional-equality hints — the
quantifier reasoning over arbitrary `Vec` length that a model checker cannot do was handled
cleanly by Verus's `Seq`/`Map` libraries and Z3. The spike-first structure surfaced the cost
early and cheaply, and the cost was low *for this obligation*. That is not a claim about the two
remaining residuals — the control-forest acyclicity in particular is a structural induction over
a graph invariant and may be materially harder.

**What's next.** The other two §3 residuals — the projection frame-lemma and the control-forest
acyclicity — are the follow-on Verus obligations. Kani did its bridge job (counter dimension on
real code, validated the payoff, sharpened this obligation); Verus has now taken the first ∀-N
step and validated that the mirror approach works end-to-end.

## 5. The projection frame-lemma — grant-summation owner-locality (LANDED)

The second §3 residual (`docs/TIER-B-CUTOFF.md` §2.3, §3(2)). The size cutoff imports a **frame
property**: a transition on entities disjoint from a violation's witness W does not perturb W's
invariant-observable state. Its substantive case is the `UnbackedGrantMap` summation
`maps_over_frame(f)` (`hypervisor.rs`), which sums `map_count` across **every** grantor's grants
naming `f` — so *a priori* any domain's transition could change it. It cannot, and the reason is
a **cross-invariant coupling**: `UnbackedGrantMap` is checked only after `MisownedGrantMap`,
which forces every grant with *live maps* over `f` to be granted by `owner(f)`. So a grant of `f`
by any `D ≠ owner(f)` carries no live maps and contributes 0 — the summation is **owner-local**,
a function of `{f, owner(f)}` (exactly the §2.2 witness), and any transition disjoint from that
witness leaves it unchanged.

`hv-verify/verus/frame_lemma.rs` proves this green (5 verified, 0 errors) over an **arbitrary-
length** grant population: `owner_local` (whole-population sum == owner-only sum, under the
misowned hypothesis); `frame_property` (the total is a function only of the owner-projection —
the form §2.3's projection construction imports); and `disjoint_append_preserves` (a concrete
non-owner `grant_access` preserves the total, the projection, and the hypothesis). This is the
same *"one invariant borrows from a relational one"* shape as the Kani finding (#20):
`UnbackedGrantMap`'s locality borrows from `MisownedGrantMap`. Fidelity managed as in §4 (the
mirror's `sum_frame` transcribes `maps_over_frame`; `misowned_ok` mirrors the `MisownedGrantMap`
check; the enumerator pins the pair on real code at small size via Tier A's `grant_p2m_3dom_cfg`).
Non-vacuity validated: dropping the misowned hypothesis or the disjoint-step guard makes Verus
reject the proof. Effort was again low (~5 lemmas). §2.3's other two bullets — slot-reuse
index-independence and the single-referrer scans — are non-cross-domain and simpler; the
summation was the only one where disjointness was non-trivial.

**Remaining: §3 residual (3)** — the control-forest acyclicity, a structural induction over the
delegation forest (design-lesson #13b). That is the last of the three, and likely the hardest
(a graph invariant, not a filtered sum).

## 6. Control-forest acyclicity — the cycle case, ∀ domain count (LANDED)

The third and last §3 residual (`docs/TIER-B-CUTOFF.md` §2.4, §3(3)), and the one with **no size
cutoff**: `ControlEdgeOrphaned` splits into an *orphan* case (local, witness 3 domains — the
cutoff covers it) and a *cycle* case (a cycle of length L needs L distinct domains, so its witness
is unbounded in domain count). §2.4 hands the cycle case to Tier C as "a structural induction
proving the delegation graph is always a forest" (design-lesson #13b).

`hv-verify/verus/control_forest_acyclic.rs` proves it green (8 verified, 0 errors) at **arbitrary
domain count**. The mechanism: `control_grant` (`hypervisor.rs`) is the only edge-*adding*
transition, and it adds an edge only in its **fresh-leaf** case (`to` did not already control the
target); if `to` already controls it, it is a no-op that preserves provenance — it never
*re-parents*, the one move that could close a cycle. A graph that only grows fresh leaves is a
forest. The proof carries a **rank certificate** (a ghost, not stored state): a `rank` strictly
decreasing along every `Via` edge (`valid_rank`) whose existence *is* acyclicity, plus `rank[h] <
node count` (`bounded`). `control_grant_preserves` / `root_stamp_preserves` show the fresh-leaf
delegation and the `DomainCreate` `Root` stamp both extend the certificate (acyclicity is
inductive), and `certificate_discharges_orphaned` shows a valid+bounded rank makes the real
provenance walk reach a `Root` within `n = domain_count` steps — exactly `ControlEdgeOrphaned`
not firing.

**The honest hard part, and how it was threaded.** As flagged when the residual was picked, any
faithful proof of the code's exact `steps ≤ n` bound needs a *pigeonhole* — a terminating walk
visits distinct nodes, so its length is bounded by the node count. This is a graph invariant, not
a filtered sum, so it was genuinely harder than §4/§5. It was threaded by folding the pigeonhole
into the invariant: `bounded` (`rank[h] < node count`) is preserved by the fresh-leaf step
*without* an explicit distinct-nodes argument, because `rank[caller] < count` by the IH and the
count grows by one. Effort landed at ~8 lemmas — more than the summation proofs (~5–7) but still
tractable; the person-months caveat did not bite even for the hardest of the three. Non-vacuity
validated: weakening the strict rank decrease or dropping the fresh-leaf precondition makes Verus
reject the proof. Same *"one property borrows from a relational one"* shape as #20/#21 —
`ControlEdgeOrphaned`'s no-cycle content is carried by the rank certificate.

**All three §3 residuals are now discharged.** What remains of the true-diamond program is Tier D
(non-interference) — and the standing caveat these proofs cover the *model* (the pure brain), not
whether the *metal* enforces it (M3+).
