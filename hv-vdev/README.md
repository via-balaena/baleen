<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `hv-vdev` — the guest's virtual devices, under the fence

**Both sides of the guest's device surface**: the register files a guest drives (a PL011 UART, a
GICv3 distributor) and the vGIC CPU interface EL2 writes. Pure `no_std`, zero `unsafe`, no
dependencies.

## The gap it exists to close

Arc ③ took every real device away from the guest — console, interrupt delivery, interrupt
controller — until `stage2::windows().device_len == 0` as a **compile-time fact**. A real isolation
result, with a cost nobody had written down:

| before ③ | after ③ |
|---|---|
| the guest touched real hardware, and **Stage-2 mediated it** — the proven artifact, with an ∀-frame refinement and an ∀-address walk behind it | the guest touched emulation code, which was proven by **nothing** |

Removing the hardware moved the guest's device surface out from under the proof. This crate moves
it back: the emulation is now pure code under the fence, so it can be **proven** rather than only
boot-witnessed.

## Where it sits

| depends on | depended on by |
|---|---|
| nothing | `hv-metal`, [`hv-verify`](../hv-verify/README.md) |

## What proves it

```
cargo kani -p hv-verify --harness <name>
```

Design docs: [`docs/VGIC-SPI-ROUTING.md`](../docs/VGIC-SPI-ROUTING.md),
[`docs/INTERRUPT-CONFINEMENT.md`](../docs/INTERRUPT-CONFINEMENT.md),
[`docs/GICD-RES0-SURFACE.md`](../docs/GICD-RES0-SURFACE.md). ⚠ On `PROOF_PATHS`.

## The reference

```
cargo doc -p hv-vdev --open
```
