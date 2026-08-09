<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `hv-hal` — the fence

**The entire surface `hv-core` is allowed to touch.** Memory, time and CPUs reach the proven logic
only through these traits — never hardware directly. 95 lines, no dependencies, and that is the
point: the fence is small enough to audit in one sitting.

## Where it sits

```
        hv-core ──┐
        hv-sim  ──┼──▶ hv-hal ◀── implemented by hv-sim (host) and hv-metal (bare metal)
        hv-metal ─┘
```

Nothing. It depends on nothing, which is what lets everything depend on it.

**Exactly two implementations exist**, and that is a deliberate cap: [`hv-sim`](../hv-sim/README.md)
makes guest memory a `Vec<u8>` and time a counter you advance by hand, so `cargo test` exercises the
scheduler; `hv-metal` plugs in real hardware virtualization behind the same traits. The same logic
runs on your laptop and on the metal, and **the only thing hardware can falsify is this thin
translation layer**.

⚠ **Architecture-neutral by standing constraint.** ARM and x86 are co-equal targets; the first
`hv-metal` backend is AArch64/EL2 because it went first, not because the fence favours it. A trait
here that names an ARM concept is a defect.

## What proves it

The fence is audited, not proven — the argument is in
[`docs/AUDIT-1-HAL-FENCE.md`](../docs/AUDIT-1-HAL-FENCE.md), which asks the only question that
matters here: **what is `hv-core` forbidden to know?** `#![forbid(unsafe_code)]` makes the "zero
unsafe" claim a build error rather than a convention.

## The reference

```
cargo doc -p hv-hal --open
```

The module doc is the real documentation. This file is the front door.
