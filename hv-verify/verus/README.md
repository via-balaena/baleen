<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `hv-verify/verus` — the Verus (∀-N) proofs (Tier C, and the Tier D spike)

These proofs are **not** compiled by cargo. They live outside `hv-verify/src/` on purpose:
Verus is a Rust *dialect* (`spec fn`/`requires`/`ensures`/`verus!{}` do not parse under stable
`rustc`, and Verus must front-end the whole crate it verifies), so — unlike the `#[cfg(kani)]`
harnesses in `../src/lib.rs`, which are ordinary Rust — a Verus file cannot be `#[cfg]`-hidden
from `cargo build`. Keeping it here guarantees `cargo test --workspace` / MSRV / clippy /
cargo-deny never see it and the pure brain stays stable-buildable. It is verified out-of-band.

## What is proven

| file | obligation | §3 residual |
|---|---|---|
| `refcount_mismatch.rs` | `RefcountMismatch` (`maps == \|live mappings\|`, `writable_maps == \|writable live mappings\|`) is preserved by grant `map` **and** `unmap`, for an **arbitrary entry table × arbitrary-length mapping sequence** — the ∀-N / scalar↔`Vec` step Kani could only `unwind`. | (1) refcount infinity |
| `frame_lemma.rs` | The **projection frame-lemma**: the grant summation `maps_over_frame(f)` is **owner-local** — under `MisownedGrantMap`, only `owner(f)`'s grants contribute, so a transition disjoint from `{f, owner(f)}` cannot perturb `UnbackedGrantMap`'s read-value at `f`. Over an **arbitrary-length** grant population. | (2) projection frame-lemma |
| `control_forest_acyclic.rs` | **Control-forest acyclicity**: `ControlEdgeOrphaned`'s cycle case, which has **no size cutoff**. A rank certificate (strictly decreasing along `Via` edges, bounded by node count) is preserved by `control_grant`'s fresh-leaf delegation and the `DomainCreate` `Root` stamp, and discharges the real provenance-walk-reaches-`Root`-within-`n` check — at **arbitrary domain count**. | (3) control-cycle acyclicity |
| `unwinding_signal.rs` **(Tier D)** | **Signal-channel local respect**: under event-channel **reciprocity** (the peer map is an involution), a domain `a` holding no port toward `b` implies `b` holds no port toward `a`, so a `send` by `b` cannot set any pending bit of `a` — `obs(a)`'s signal projection is preserved by a step from a `b` with no signal channel to `a`. Over an **arbitrary port population**. | Tier D — non-interference |
| `unwinding_control.rs` **(Tier D)** | **Control-channel local respect**: the `SchedSetAffinity` authority **guard** (`caller == target ∨ controls[caller][target]`) forces a step by a `b` that does not control `a` (and `b ≠ a`) to write `target ≠ a`, so `a`'s vCPU-affinity projection is untouched; a caller-only scheduler op (write confined to `b`'s rows) preserves `a`'s vCPU rows for free. Over an **arbitrary vCPU population**. *Finding: this channel's locality comes from a transition **guard** (#9), not a relational state invariant.* | Tier D — non-interference |
| `unwinding_create.rs` **(Tier D)** | **Creation-channel local respect**: the `DomainCreate` **guards** (`may_create[caller] ∧ target Dead`) force a step by a `b` with no creation channel to `a` (`¬(may_create[b] ∧ ¬live[a])`) to lift a slot `≠ a`, so `life[a]` — the only `obs`-visible effect of creation (a `Dead` slot is a clean shell, so creation adds no resources) — is unchanged. Over **arbitrary domain count**. *The **second** guard-channel: the four direct channels split two-and-two — memory/signal borrow from a state invariant, authority/creation come from a guard.* | Tier D — non-interference |
| `unwinding_destroy.rs` **(Tier D)** | **The `DomainDestroy` cascade** — the only *multi-domain* transition (intransitive reach). Its compound teardown (`close_all`/`clear_unbound_into`, `revoke_grants_to`/`drain_maps_of`) touches a *third* domain `a`'s ports, grant rows, and frame references — but every touch is conditioned on `a`→`c` grant or `a`→`c` port (the teardown-reach term). Proven: the port + grant-row sub-ops preserve `a`'s state when it has no reach to `c` (guard-shaped); the drain preserves `a`'s frame refs via the grant `map`-identity (`Seq`-induction, borrows-from-a-relational-invariant); and the intransitive-channel heart — `¬(b ⇝ a)` + authorized destroy of `c` ⟹ `a` has no reach to `c`. Over **arbitrary domain + partner count**. *The cascade composes **both** channel kinds in one transition.* | Tier D — non-interference |
| `noninterference_theorem.rs` **(Tier D capstone)** | **The whole-system non-interference theorem** — the Rushby **unwinding theorem** assembling the per-transition lemmas over arbitrary executions. **Theorem A** (from **local respect**, which the five lemmas above discharge): a domain `a` sees a *constant* observation across any execution of actions by principals that do not interfere with it — unrelated activity is invisible. **Theorem B** (from local respect + **step consistency**): two executions that start `obs(a)`-equivalent and agree on each actor's observation stay `obs(a)`-equivalent — `a`'s view is determined *entirely* by the inputs authorized to flow to it. Proven generically over `obs`/`step`/`actor`/`interferes`. | Tier D — non-interference |

`refcount_mismatch.rs` is the keystone residual (`docs/TIER-B-CUTOFF.md` §3(1),
`docs/TIER-C-SPIKE.md` §3–4). Proving it discharges — for *all* sizes — the two `kani::assume`s
the spike's unmap harness could only assert (`maps ≥ 1`; read-only ⇒ `writable_maps ≤ maps − 1`),
closing the coupling the Kani finding (design-lesson #20) surfaced.

`frame_lemma.rs` discharges the substantive case of residual (2) (`docs/TIER-B-CUTOFF.md` §2.3):
the frame property the size cutoff imports. Of §2.3's three bullets (slot-reuse
index-independence, the grant-summation owner-locality, and the single-referrer scans), the
summation is the only cross-domain one, so it is the only non-trivial case — and its locality
*borrows* from `MisownedGrantMap`, the same "one invariant borrows from a relational one" shape
the Kani spike found (#20).

`control_forest_acyclic.rs` discharges residual (3) (`docs/TIER-B-CUTOFF.md` §2.4) — the one Tier
B flagged as having **no size cutoff**, because a cycle of length L needs L distinct domains. The
proof is a structural induction that the delegation graph is always a forest (design-lesson #13b):
a rank certificate is preserved by the only edge-adding transition, `control_grant`'s fresh-leaf
case (it never re-parents an existing controller — the move that could close a cycle). The
pigeonhole the exact `steps ≤ n` bound needs is folded into the certificate (`rank[h] < node
count`). **With this, all three §3 residuals are discharged.**

## Running it

```sh
# Install Verus (pinned; arm64-macos shown — swap the asset for your platform):
VTAG=release/0.2026.07.12.0b42f4c
curl -sL -o verus.zip \
  "https://github.com/verus-lang/verus/releases/download/$VTAG/verus-0.2026.07.12.0b42f4c-arm64-macos.zip"
unzip -q verus.zip -d ~/.local/verus
VERUS=~/.local/verus/verus-arm64-macos/verus

# Verify each proof (exit 0 = every proof discharged):
$VERUS --crate-type=lib hv-verify/verus/refcount_mismatch.rs        # → 8 verified, 0 errors
$VERUS --crate-type=lib hv-verify/verus/frame_lemma.rs              # → 5 verified, 0 errors
$VERUS --crate-type=lib hv-verify/verus/control_forest_acyclic.rs   # → 8 verified, 0 errors
$VERUS --crate-type=lib hv-verify/verus/unwinding_signal.rs         # → 2 verified, 0 errors  (Tier D)
$VERUS --crate-type=lib hv-verify/verus/unwinding_control.rs        # → 3 verified, 0 errors  (Tier D)
$VERUS --crate-type=lib hv-verify/verus/unwinding_create.rs         # → 2 verified, 0 errors  (Tier D)
$VERUS --crate-type=lib hv-verify/verus/unwinding_destroy.rs        # → 7 verified, 0 errors  (Tier D)
$VERUS --crate-type=lib hv-verify/verus/noninterference_theorem.rs  # → 5 verified, 0 errors  (Tier D capstone)
```

CI runs exactly this in the `verus preservation proofs` job of
`.github/workflows/deep-verify.yml` (scheduled + dispatch, **not** a required PR check — same
class as the Kani job and the enumerator sweeps), on the `x86-linux` build, pinned to the same
release tag so a Verus release cannot silently change proof semantics.

## Fidelity — how the mirror provably tracks shipped code

Verus verifies a *mirror* (dialect), so the mirror must faithfully *be* the shipped transition.
Three anchors, all documented inline in `refcount_mismatch.rs`:

1. **Shared arithmetic, transcribed.** `counts_after_map`/`counts_after_unmap` here transcribe
   `hv_core::grant::System::counts_after_map`/`counts_after_unmap` expression-for-expression —
   the same functions production and the Kani proof already share (design-lesson #14c).
2. **The predicate mirrors `first_violation`.** `matches`/`count` are the exact per-entry
   filter-and-count of `RefcountMismatch` in `hv-core/src/grant.rs`.
3. **The enumerator pins fidelity on the real code at small size.** `hv-sim::enumerate`
   exhaustively checks `RefcountMismatch` on the *actual* `System` for small configs (finds
   nothing); Kani checks the ∀-magnitude axis on real code; this file adds the ∀-length axis on
   the mirror. Three tools, complementary axes of one obligation.

## Non-vacuity (the "remove the fix → counterexample" check)

The proofs have teeth — dropping a load-bearing hypothesis makes Verus reject them (verified by
hand; each reproduces in seconds):

| file | perturbation | result |
|---|---|---|
| `refcount_mismatch.rs` | `map` target scalar `counts_after_map(..)` → `(maps, wmaps)` (drop the `+1`) | `postcondition not satisfied` |
| `refcount_mismatch.rs` | `counts_after_map` writable half `wmaps + b2n(w)` → `wmaps` (drop the writable bump) | `postcondition not satisfied` |
| `refcount_mismatch.rs` | `counts_after_unmap(..)` → `(maps, wmaps)` (no decrement) | `postcondition not satisfied` |
| `frame_lemma.rs` | drop `misowned_ok` from `owner_local`'s `requires` | `postcondition not satisfied` |
| `frame_lemma.rs` | drop the `g.frame != f \|\| g.count == 0` guard on the disjoint step | `postcondition not satisfied` |
| `control_forest_acyclic.rs` | weaken the strict rank decrease `rank[d] < rank[h]` → `≤` | `postcondition not satisfied` |
| `control_forest_acyclic.rs` | drop the `is_absent(col[to])` fresh-leaf precondition (allow re-parenting) | `postcondition not satisfied` |
| `unwinding_signal.rs` | drop the `involution(peer)` (reciprocity) hypothesis from `no_port_toward_is_symmetric` | `assertion failed` |
| `unwinding_control.rs` | drop the `!controls.contains((b, a))` hypothesis from `set_affinity_target_not_a` | `postcondition not satisfied` |
| `unwinding_create.rs` | drop the `!creation_channel(..)` hypothesis from `create_target_not_a` | `postcondition not satisfied` |
| `unwinding_destroy.rs` | drop the `!granted_to_some(a, c)` hypothesis from `no_c_map_over_a_frame` | `assertion failed` |
| `unwinding_destroy.rs` | drop the teardown-reach `forall` hypothesis from `no_channel_no_reach_to_c` | `postcondition not satisfied` |
| `noninterference_theorem.rs` | drop the `local_respect()` premise from Theorem A | `assertion failed` |
| `noninterference_theorem.rs` | drop the `step_consistent()` premise from Theorem B | `assertion failed` |

## What's next

**All three §3 residuals are now discharged** (refcount infinity, projection frame-lemma,
control-forest acyclicity) — Tier C is complete. `unwinding_signal.rs`,
`unwinding_control.rs`, `unwinding_create.rs`, and `unwinding_destroy.rs` are the **Tier D**
per-transition local-respect lemmas on the deductive axis. Together with `frame_lemma.rs` (the
memory channel, from Tier C), **every transition class is discharged**: the four direct channels
(memory/signal borrow from a state invariant; authority/creation come from a guard) *and* the
multi-domain `DomainDestroy` cascade (which composes both kinds — guard-shaped port/grant-revoke
sub-ops + an invariant-borrowing drain). `noninterference_theorem.rs` is the **capstone**: the
Rushby **unwinding theorem** assembling those per-transition local-respect lemmas into whole-system
non-interference over arbitrary executions. **With it, Tier D — and the true-diamond program A→D — is
complete at the model level:** Tiers A–C prove every invariant holds ∀-N, and Tier D proves those
invariants *collectively imply* isolation (that we are checking the *right* things) — validated on
the real code by the enumerator **bridge** (`hv-sim/src/noninterference.rs`) and proven ∀-N here. See
`docs/TIER-D-NONINTERFERENCE.md`, and `docs/TIER-C-SPIKE.md` for the honest scope of what these ∀-N
model proofs do and don't cover (they cover the *model* — the pure brain; whether the *metal*
enforces it is M3+).
