<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `hv-verify` — where the proofs live

**Every deductive proof in the project is here**, and its subjects are elsewhere: a crate is proven
from outside itself. Two tools, two jobs:

| tool | what it does | run it |
|---|---|---|
| **Kani** (`src/lib.rs`) | bounded model checking — exhaustive over a bounded state space | `cargo kani -p hv-verify --harness <name>` |
| **Verus** (`verus/`) | ∀-N deductive proofs — the obligations enumeration provably cannot reach | see [`verus/README.md`](verus/README.md) |

```
cargo xtask kani-harnesses    # the Kani corpus, by name
cargo xtask verus-counts      # the Verus corpus, by count
```

⚠ **Both are REQUIRED CI gates** (`kani proofs (PR)`, `verus proofs (PR)`) — blocking on `main`, and
they run only when a `PROOF_PATHS` file changes. The Kani gate is expensive (measured 16m 57s in CI
for a full run), which is why the path filter exists and why the script deciding it is itself tested
(`.github/scripts/detect-proof-changes-test.sh`).

## Why two tools

Tier B proved the depth axis for every bounded-state configuration by saturation, then handed Tier C
three obligations **enumeration provably cannot reach**, because they quantify over all states
rather than enumerate small ones. The cleanest: `grant::map` bumps a `u32` refcount with no cap, so
the reachable set is genuinely infinite along that axis and no model checker can close it. Verus
discharges what Kani structurally cannot.

★ Read [`docs/TIER-B-CUTOFF.md`](../docs/TIER-B-CUTOFF.md) →
[`docs/TIER-C-SPIKE.md`](../docs/TIER-C-SPIKE.md) →
[`docs/TIER-D-NONINTERFERENCE.md`](../docs/TIER-D-NONINTERFERENCE.md), in that order.

## Where it sits

| depends on | depended on by |
|---|---|
| [`hv-core`](../hv-core/README.md), [`hv-s2`](../hv-s2/README.md), [`hv-vdev`](../hv-vdev/README.md), [`hv-part`](../hv-part/README.md) — its four subjects | nothing. A prover is a leaf |

## The reference

```
cargo doc -p hv-verify --open
```
