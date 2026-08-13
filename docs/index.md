<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Baleen

**A static-partitioning separation kernel for AArch64/EL2 — built so that its claims can be checked
rather than believed.**

Two unmodified Alpine Linux kernels boot on it, each behind its own machine-checked Stage-2 page
tables, and each is refused *by the hardware* when it reaches for the other's memory. The refusal is
verified, not asserted: the hypervisor confirms the address is unmapped in the faulting guest's
image, resolves to itself in the peer's live image, and holds the peer's loaded kernel.

It owns no real device MMIO at all. The Stage-2 device pass-through window is zero, and that is a
compile-time assertion rather than a convention.

[Source on GitHub](https://github.com/via-balaena/baleen) · Apache-2.0 / MIT

---

## Start here: the verification catching something real

**[Three green test tiers, one false property](CASE-STUDY-WORK-CONSERVATION.md)**

A scheduler property that a seeded simulation, a fuzz target **and** an exhaustive enumerator all
reported green — while it was false. One vCPU pinned away from the lowest idle CPU stopped the
machine permanently, with every safety invariant holding throughout.

It is the shortest honest answer to "does any of this verification actually do anything", and it
carries two things meant to travel beyond this project: a technique for stating a property against
the implementation's own acceptance function, and the reason three independent test tiers can share
a single blind spot.

*Written for a reader with an hour and no context.*

---

## What is claimed, and at what strength

The project's organising discipline is that these three words never blur into one:

| | |
|---|---|
| **Proven** | the model's isolation invariants and the emitter that refines them — machine-checked over symbolic inputs at bounded size, with the unbounded-size half carried deductively |
| **Demonstrated** | the metal — real kernels, real hardware refusals, under required CI gates on every pull request |
| **Argued** | the composition step from the generic non-interference theorem to concrete Baleen — prose over proved lemmas, declared rather than hidden |

Every figure behind those rows lives in the [repository README](https://github.com/via-balaena/baleen#readme),
because the counts there are **gated** — `cargo xtask ci` fails on a stale number in that file as
readily as on a broken test. This page deliberately restates none of them, so that it cannot drift
away from the artifact it describes.

---

## Check it yourself

Nothing here asks to be taken on trust. The fastest honest answer is a command:

```sh
cargo xtask ci          # fmt, clippy, tests, and every documentation and corpus gate
cargo xtask qemu-test   # the hypervisor boots at EL2 under QEMU and asserts its boot markers
```

And the proofs, which need their own toolchains:

```sh
cargo xtask kani-harnesses   # what the Kani corpus contains, by name
cargo xtask verus-counts     # the Verus obligations, by count
```

---

## What it is not

This is the part most projects leave out, and it is the reason to trust the rest.

- **Not a general-purpose hypervisor.** Two compile-time guests, no toolstack, no dynamic
  configuration. Those are design requirements for a separation kernel, not features yet to arrive.
- **Not running on silicon.** Everything on the metal is QEMU today. What that does and does not
  mean has [its own document](QEMU-AND-METAL.md), and it should be read before believing any sentence
  containing the word "metal".
- **Not finished being wrong.** The repository keeps an *honest ledger* of what is not closed —
  including refuted ideas left in place with their reasoning, so that nobody re-pitches them and
  nobody mistakes a gap for an oversight.

---

## Where this is going

A powered exoskeleton with a learned control policy and a safety monitor is a mixed-criticality
system: an untrusted controller that must never be able to violate the monitor. The standard
architecture for that — runtime assurance, the simplex pattern — wants exactly what a separation
kernel provides, and the properties listed above as limitations are requirements in that role.

That is a destination rather than a claim. It is recorded here so the work has a stated purpose
rather than an implied one.

---

## Documentation

The [full documentation index](README.md) covers the deductive program, the architecture audits, the
metal isolation thesis arc by arc, device assignment and the SMMU, and the interrupt surface. It is
engineering documentation — each document records what was established, what was refuted, and what
was left open at the moment its arc closed.

If you work on separation kernels, bounded model checking, or deductive verification of systems code
and something here looks wrong, that is the most useful thing you could tell me — open an issue.
