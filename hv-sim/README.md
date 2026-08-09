<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `hv-sim` — the deterministic twin

**The host-side implementation of the [`hv-hal`](../hv-hal/README.md) fence**, plus the scenario
runner that drives [`hv-core`](../hv-core/README.md) through thousands of seeded interleavings on a
laptop.

Guest memory is a `Vec<u8>`. Time is a counter you advance by hand. A VMEXIT is a function call.
**No VM required, and ~80% of development is meant to happen here.**

## Why a twin and not a mock

A mock is written to make a test pass. This is the *same* `hv-core`, driven through the *same*
trait surface the metal drives it through — so a scenario that fails here is a bug in the
hypervisor, not in the harness. That property is what makes `cargo test` meaningful at all.

## Where it sits

| depends on | depended on by |
|---|---|
| [`hv-hal`](../hv-hal/README.md), [`hv-core`](../hv-core/README.md), [`hv-s2`](../hv-s2/README.md) | the test suites, `hv-fuzz` |

## Running it

```
cargo test --workspace     # the seeded scenarios, among everything else
cargo xtask sweeps         # the exhaustive enumerators, by name
```

`enumerate.rs` holds the exhaustive sweeps and `noninterference.rs` the property from
[`docs/TIER-D-NONINTERFERENCE.md`](../docs/TIER-D-NONINTERFERENCE.md) — the definition of what
"isolation" is allowed to mean.

## The reference

```
cargo doc -p hv-sim --open
```
