<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Tier C — the deductive spike (Kani bridge → Verus)

*Status: tooling decided, repo/CI shape landed, Kani bridge green, and the **Verus ∀-N phase's
first obligation** (`RefcountMismatch` preserved over arbitrary table size) proven green (§4).
This is Tier C in progress — a validated end-to-end approach, not the finished ∀-N program. Read
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

**What's next.** The other two §3 residuals — the projection frame-lemma (per-transition
write⟂read disjointness) and the control-forest acyclicity (structural induction over the
delegation forest, design-lesson #13b) — are the follow-on Verus obligations. Kani did its
bridge job (counter dimension on real code, validated the payoff, sharpened this obligation);
Verus has now taken the first ∀-N step and validated that the mirror approach works end-to-end.
