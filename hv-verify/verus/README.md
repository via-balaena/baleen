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
| `unwinding_control.rs` **(Tier D)** | **Control-channel local respect**: the `SchedSetAffinity` authority **guard** (`caller == target ∨ controls[caller][target]`) forces a step by a `b` that does not control `a` (and `b ≠ a`) to write `target ≠ a`, so `a`'s vCPU-affinity projection is untouched; a caller-only scheduler op (write confined to `b`'s rows) preserves `a`'s vCPU rows for free. Over an **arbitrary vCPU population**. *Finding: this channel's locality comes from a transition **guard** (#9), not a relational state invariant — the simplest of the three.* | Tier D — non-interference |

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

## What's next

**All three §3 residuals are now discharged** (refcount infinity, projection frame-lemma,
control-forest acyclicity) — Tier C is complete. `unwinding_signal.rs` and
`unwinding_control.rs` are the **Tier D** per-channel local-respect lemmas on the deductive
axis: non-interference *unwinding* proven end-to-end for the signal channel (borrows from
event-channel reciprocity) and the control/affinity channel (locality straight from the
`SchedSetAffinity` authority guard — the simplest of the three). Together with `frame_lemma.rs`
(the memory channel, from Tier C), that is **three of the direct channels** done. The remaining
Tier D work — the creation channel and the multi-domain `DomainDestroy` cascade, assembled into
whole-system non-interference — is scoped in `docs/TIER-D-NONINTERFERENCE.md`, alongside the
enumerator
**bridge** (`hv-sim/src/noninterference.rs`) that validates the property definition on the real
code at small size. See `docs/TIER-C-SPIKE.md` for the honest scope of what these ∀-N model
proofs do and don't cover (they cover the *model* — the pure brain; whether the *metal* enforces
it is M3+).
