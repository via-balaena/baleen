<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `hv-core` — the brain

**All of the hypervisor's *thinking*, as a `no_std` library with zero `unsafe`:** hypercall
dispatch and the state machines behind it — the scheduler, the grant table, event channels, the
`p2m`, the domain lifecycle, policy.

It touches hardware only through [`hv-hal`](../hv-hal/README.md), so the code that runs on the metal
is the code that is unit-tested, fuzzed and model-checked on a laptop. **This is the crate the
proofs are about.**

## Where it sits

| depends on | depended on by |
|---|---|
| [`hv-hal`](../hv-hal/README.md) — and nothing else | `hv-metal`, [`hv-sim`](../hv-sim/README.md), [`hv-s2`](../hv-s2/README.md), [`hv-verify`](../hv-verify/README.md), `hv-fuzz` |

## What proves it

Everything, by four independent methods — which is the whole argument of the project:

```
cargo test --workspace                      # unit + property tests, and hv-sim's seeded scenarios
cargo xtask sweeps                          # exhaustive enumeration over bounded configurations
cargo kani -p hv-verify --harness <name>    # bounded model checking (the Kani corpus)
cargo xtask kani-harnesses                  # what that corpus contains, by name
```

The harnesses themselves live in [`hv-verify`](../hv-verify/README.md), not here — a crate proves
its subject from outside it.

★ **Start with [`docs/TIER-B-CUTOFF.md`](../docs/TIER-B-CUTOFF.md)** for why checking small
configurations exhaustively says anything about large ones. The full reading order is in
[`docs/README.md`](../docs/README.md).

## The reference

```
cargo doc -p hv-core --open
```
