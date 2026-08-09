<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `hv-part` — which slot owns what

**How one machine is partitioned among guest slots**: which model frames, which page tables, which
IPA window, which domain id, which vCPU affinities. Pure `no_std` arithmetic, zero `unsafe`, no
dependencies.

★ **Every derivation here is `slot`-indexed arithmetic, and every one is a place where an off-by-one
crosses a domain boundary** — the exact failure the isolation thesis exists to exclude.

## Why it is a crate and not four `const fn`s in `hv-metal`

It *was* four `const fn`s in `hv-metal`, guarded by `const assert!`s evaluated at **the sizes the
board deploys** — two guests, two vCPUs. That is a check of two cases. `hv-metal` is
workspace-excluded, so nothing in it is reachable by [`hv-verify`](../hv-verify/README.md), and no
amount of care there turns two cases into all of them.

Under the fence the same arithmetic is ∀-checkable: `hv-metal` keeps its compile-time guards
unchanged (the derivations are still `const fn`), and disjointness is proven for a **symbolic**
partition rather than for the one this board happens to have.

## Where it sits

| depends on | depended on by |
|---|---|
| nothing | `hv-metal`, [`hv-verify`](../hv-verify/README.md) |

## What proves it

```
cargo kani -p hv-verify --harness <name>
```

⚠ On `PROOF_PATHS` — a PR touching this crate pays the full Kani gate.

## The reference

```
cargo doc -p hv-part --open
```
