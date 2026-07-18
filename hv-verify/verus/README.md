<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `hv-verify/verus` — the Verus (∀-N) phase of Tier C

These proofs are **not** compiled by cargo. They live outside `hv-verify/src/` on purpose:
Verus is a Rust *dialect* (`spec fn`/`requires`/`ensures`/`verus!{}` do not parse under stable
`rustc`, and Verus must front-end the whole crate it verifies), so — unlike the `#[cfg(kani)]`
harnesses in `../src/lib.rs`, which are ordinary Rust — a Verus file cannot be `#[cfg]`-hidden
from `cargo build`. Keeping it here guarantees `cargo test --workspace` / MSRV / clippy /
cargo-deny never see it and the pure brain stays stable-buildable. It is verified out-of-band.

## What is proven

| file | obligation |
|---|---|
| `refcount_mismatch.rs` | `RefcountMismatch` (`maps == \|live mappings\|`, `writable_maps == \|writable live mappings\|`) is preserved by grant `map` **and** `unmap`, for an **arbitrary entry table × arbitrary-length mapping sequence** — the ∀-N / scalar↔`Vec` step Kani could only `unwind`. |

This is the keystone Tier C residual (`docs/TIER-B-CUTOFF.md` §3(1), `docs/TIER-C-SPIKE.md`
§3–4). Proving it discharges — for *all* sizes — the two `kani::assume`s the spike's unmap
harness could only assert (`maps ≥ 1`; read-only ⇒ `writable_maps ≤ maps − 1`), closing the
coupling the Kani finding (design-lesson #20) surfaced.

## Running it

```sh
# Install Verus (pinned; arm64-macos shown — swap the asset for your platform):
VTAG=release/0.2026.07.12.0b42f4c
curl -sL -o verus.zip \
  "https://github.com/verus-lang/verus/releases/download/$VTAG/verus-0.2026.07.12.0b42f4c-arm64-macos.zip"
unzip -q verus.zip -d ~/.local/verus

# Verify (exit 0 = every proof discharged):
~/.local/verus/verus-arm64-macos/verus --crate-type=lib hv-verify/verus/refcount_mismatch.rs
# → verification results:: 8 verified, 0 errors
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

The proof has teeth — perturbing the arithmetic makes Verus reject it (verified by hand; each
reproduces in seconds):

| perturbation | result |
|---|---|
| `map` target scalar `counts_after_map(..)` → `(maps, wmaps)` (drop the `+1`) | `postcondition not satisfied` |
| `counts_after_map` writable half `wmaps + b2n(w)` → `wmaps` (drop the writable bump) | `postcondition not satisfied` |
| `counts_after_unmap(..)` → `(maps, wmaps)` (no decrement) | `postcondition not satisfied` |

## What's next

The remaining §3 residuals — the projection frame-lemma (per-transition write⟂read
disjointness) and the control-forest acyclicity (structural induction over the delegation
forest, design-lesson #13b) — are the follow-on Verus obligations. See `docs/TIER-C-SPIKE.md`.
