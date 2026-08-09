<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `hv-s2` — Stage-2 emission, factored out of the `unsafe` metal

**Turns the proven `p2m` relation into a hardware page-table image** — the bytes an ARM MMU walks —
as pure `no_std` code with zero `unsafe`.

This is the crate that carries the project's central refinement: *the page tables the hardware
obeys are the page tables the proof is about.* It lives outside `hv-metal` for one reason —
`hv-metal` is workspace-excluded and cannot be reached by the verifier, so arithmetic that stays
there can only ever be checked at the sizes one board deploys.

## Where it sits

| depends on | depended on by |
|---|---|
| [`hv-core`](../hv-core/README.md) | `hv-metal`, [`hv-sim`](../hv-sim/README.md), [`hv-verify`](../hv-verify/README.md), `hv-fuzz` |

## What it also owns

`arm64::memtype::MemoryType` — **the single declaration of what a memory type IS**, encoded per
regime (a Stage-1 `MAIR` byte and a Stage-2 `MemAttr` nibble are different encoding spaces for the
same thing). Mutating it is a compile error in `hv-metal`. Before this existed the agreement between
EL2's own mappings and its guests' was two literals in two crates agreeing *in prose*.

## What proves it

```
cargo kani -p hv-verify --harness <name>   # incl. the ∀-address walk and ∀-frame refinement
cargo xtask sweeps
```

★ [`docs/AUDIT-2-P2M-STAGE2.md`](../docs/AUDIT-2-P2M-STAGE2.md) is the refinement argument;
[`docs/STAGE2-REFINEMENT-FORALL-N.md`](../docs/STAGE2-REFINEMENT-FORALL-N.md) is the same claim for
all N. ⚠ This crate is on `PROOF_PATHS`, so touching it makes a PR pay the full Kani gate.

## The reference

```
cargo doc -p hv-s2 --open
```
