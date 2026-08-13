---
# ⚠ This front matter exists ONLY so GitHub Pages renders this file as HTML.
# GitHub's `jekyll-optional-front-matter` plugin, which turns the other markdown in this
# directory into pages, deliberately SKIPS files named README — so without this block the
# site served this index as raw markdown while every neighbouring page rendered, and the
# landing page's "full documentation index" link dumped source at a first-time reader.
# Both GitHub's markdown viewer and Jekyll strip this block, so it is invisible in the repo.
title: Documentation index
---

<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `docs/` — what is in here, and what to read first

**36 documents.** (Plus this index and the [site landing page](index.md) — the only two files
`doc-index` treats as indexes rather than classified documents.)
They are not a manual and they are not in order; each one was
written to close a specific arc, and each records *what was established, what was refuted, and what
was left open* at the moment it closed.

⚠ **This index is GATED** (`cargo xtask doc-index`): every file in `docs/` appears below exactly
once, and every entry resolves. A new document that is not listed here fails CI. That is deliberate
— an index maintained by memory is a corpus claim nothing checks, and this project has been bitten by
those enough times to gate all six of its other corpora.

---

## ▶ Where to start, by what you actually want

**"Is any of this real?"** — the fastest honest answer is a command, not a document.

```
cargo xtask ci          # fmt, clippy, tests, and every doc/corpus gate
cargo xtask qemu-test   # the hypervisor boots on the metal, under QEMU
```

Then read the root [`README.md`](../README.md)'s *"What this is, honestly"* section, which states the
limits before the claims, and [`QEMU-AND-METAL.md`](QEMU-AND-METAL.md) — **what testing against QEMU
does and does not mean**. Read that one before believing any sentence containing the word "metal".

**"Show me the verification catching something."** — [`CASE-STUDY-WORK-CONSERVATION.md`](CASE-STUDY-WORK-CONSERVATION.md): a real defect, why three
green test tiers missed it, and what the harness did differently. **Start here if you have an hour
and no context.**

**"How does the proof work?"** — [`TIER-B-CUTOFF.md`](TIER-B-CUTOFF.md) →
[`TIER-C-SPIKE.md`](TIER-C-SPIKE.md) → [`TIER-D-NONINTERFERENCE.md`](TIER-D-NONINTERFERENCE.md), in
that order. They build: bounded exhaustive checking, then a deductive spike, then the property that
makes "isolation" mean something.

**"How does the code get from the proof to the hardware?"** —
[`AUDIT-2-P2M-STAGE2.md`](AUDIT-2-P2M-STAGE2.md) (the refinement) →
[`STAGE2-REFINEMENT-FORALL-N.md`](STAGE2-REFINEMENT-FORALL-N.md) (the same, ∀-N) →
[`ARC-6-M5-THESIS.md`](ARC-6-M5-THESIS.md) (the assembled claim).

**"What is not proven?"** — the honest ledger lives in the root [`README.md`](../README.md), not
here. Individual docs each end with their own residuals, which is where the ledger's items come from.

---

## ⚠ The filename trap, stated because it will catch you

**The hyphen carries meaning that nothing else records.** `ARC-N-M5-*` is the numbered arc itself —
what it *built*. `ARCN-*` (no hyphen) is a companion document for that same arc — a property it made
checkable, or a sub-arc. So there are **two documents titled "M5 Arc 4"** and **two titled "M5
Arc 5"**, and they are not duplicates:

| both say | the hyphenated one is | the unhyphenated one is |
|---|---|---|
| M5 Arc 4 | [`ARC-4-M5-VIRTIO-BLK-COW.md`](ARC-4-M5-VIRTIO-BLK-COW.md) — what was built | [`ARC4-CONCURRENCY-PREDICATE.md`](ARC4-CONCURRENCY-PREDICATE.md) — the predicate made checkable |
| M5 Arc 5 | [`ARC-5-M5-GUEST-INTERFACE.md`](ARC-5-M5-GUEST-INTERFACE.md) — what was built | [`ARC5-CONTENT-NON-INHERITANCE.md`](ARC5-CONTENT-NON-INHERITANCE.md) — the property it had to establish |

⛔ **And `ARC-4-TRAP-AND-SERVICE.md` is M4's Arc 4, not M5's** — a third "Arc 4", from an earlier
milestone entirely.

The files are **not being renamed**: 235 cited paths across the docs and READMEs point at them, and a
rename trades a stated trap for a silent one.

---

## Case studies — what the verification actually caught

*Written for a reader who does not know this project and has an hour. Each one is a single defect,
end to end: what was claimed, what was false, why the existing tests missed it, and what the proof
did that they could not.*

| document | what it establishes |
|---|---|
| [`CASE-STUDY-WORK-CONSERVATION.md`](CASE-STUDY-WORK-CONSERVATION.md) | a scheduler property that a seeded simulation, a fuzz target **and** an exhaustive enumerator all reported green while it was false — one pinned vCPU stopped the machine permanently, with every safety invariant holding. The Kani harness that caught it uses the **mechanism as its own oracle**, which is the transferable technique; the lesson is *count the axes your generators move, not the tiers that assert* |

## The deductive program — the model, proven

*What is true of the hypervisor's logic, independent of any hardware.*

| document | what it establishes |
|---|---|
| [`TIER-B-CUTOFF.md`](TIER-B-CUTOFF.md) | the cutoff / small-scope-completeness argument — why checking small configurations exhaustively says something about all of them |
| [`TIER-C-SPIKE.md`](TIER-C-SPIKE.md) | the deductive spike: the Kani bridge into Verus |
| [`TIER-D-NONINTERFERENCE.md`](TIER-D-NONINTERFERENCE.md) | non-interference — the property definition and the bridge spike. **The longest document here, and the one that defines what "isolation" is allowed to mean** |
| [`STAGE2-REFINEMENT-FORALL-N.md`](STAGE2-REFINEMENT-FORALL-N.md) | the Stage-2 refinement for all N — "Tier C for the metal" |

## The architecture audits — where the seams are, and whether they hold

*Each audit interrogates one boundary. They are the most useful docs for a reader who wants to know
where the argument could be wrong.*

| document | what it establishes |
|---|---|
| [`AUDIT-1-HAL-FENCE.md`](AUDIT-1-HAL-FENCE.md) | the `hv-hal` fence — what the proven core is forbidden to know about hardware |
| [`AUDIT-2-P2M-STAGE2.md`](AUDIT-2-P2M-STAGE2.md) | the `p2m` → Stage-2 refinement: the proof's page tables become the hardware's |
| [`AUDIT-3-NON-INTERFERENCE.md`](AUDIT-3-NON-INTERFERENCE.md) | non-interference as the thesis, bridged to Tier D |
| [`AUDIT-4-CONCURRENT-STAGE2.md`](AUDIT-4-CONCURRENT-STAGE2.md) | two-set Stage-2 emission — isolation with two domains actually running |
| [`AUDIT-5-VIRTQUEUE-GRANT.md`](AUDIT-5-VIRTQUEUE-GRANT.md) | the virtqueue is a **proven grant**, not a hole punched through the isolation |
| [`AUDIT-6-VIRTIO-BLK-COW.md`](AUDIT-6-VIRTIO-BLK-COW.md) | the copy-on-write disk keeps guest writes off the shared template |
| [`AUDIT-7-INTERRUPT-SURFACE.md`](AUDIT-7-INTERRUPT-SURFACE.md) | whether the interrupt/timer/PSCI surface opens a cross-domain channel |

## M5 — the metal isolation thesis, arc by arc

*The program that took the proven model to running hardware. Read [`ARC-6-M5-THESIS.md`](ARC-6-M5-THESIS.md)
first if you want the conclusion before the construction.*

| document | what it establishes |
|---|---|
| [`ARC-0-M5-LIFECYCLE.md`](ARC-0-M5-LIFECYCLE.md) | the lifecycle: a reborn slot inherits nothing |
| [`ARC-1-M5-SCHEDULER.md`](ARC-1-M5-SCHEDULER.md) | the concurrent scheduler — two vCPUs time-slicing on real hardware |
| [`ARC-2-M5-CONCURRENT-ISOLATION.md`](ARC-2-M5-CONCURRENT-ISOLATION.md) | concurrent inter-domain isolation: two domains, distinct VMIDs |
| [`ARC-3-M5-VIRTIO-CONSOLE.md`](ARC-3-M5-VIRTIO-CONSOLE.md) | the virtio-mmio console — the ring **is** a proven grant |
| [`ARC-4-M5-VIRTIO-BLK-COW.md`](ARC-4-M5-VIRTIO-BLK-COW.md) | virtio-blk with copy-on-write template storage |
| [`ARC4-CONCURRENCY-PREDICATE.md`](ARC4-CONCURRENCY-PREDICATE.md) | the concurrency predicate, made checkable rather than argued |
| [`ARC-5-M5-GUEST-INTERFACE.md`](ARC-5-M5-GUEST-INTERFACE.md) | the guest hardware interface: interrupts, timer, PSCI |
| [`ARC5-CONTENT-NON-INHERITANCE.md`](ARC5-CONTENT-NON-INHERITANCE.md) | content non-inheritance — the metal's half of "a reborn tenant inherits nothing" |
| [`ARC6A-SPAN-REFINEMENT.md`](ARC6A-SPAN-REFINEMENT.md) | the refinement learns SPAN |
| [`ARC6B-LINUX-ON-THE-PROVEN-EMITTER.md`](ARC6B-LINUX-ON-THE-PROVEN-EMITTER.md) | a **real Linux kernel** running behind the proven emitter |
| [`ARC-6-M5-THESIS.md`](ARC-6-M5-THESIS.md) | the thesis assembled — the finale, and the shortest document here |

## M4 — trap-and-service

| document | what it establishes |
|---|---|
| [`ARC-4-TRAP-AND-SERVICE.md`](ARC-4-TRAP-AND-SERVICE.md) | the proof touches a guest: the first trap serviced by proven logic. ⚠ **M4's Arc 4** — see the filename trap above |

## Device assignment and the SMMU

*Can a device be given to a guest without giving it the machine? Rungs 2 → 3 → 4a → 4b.*

| document | what it establishes |
|---|---|
| [`SMMU-STREAM-TABLE.md`](SMMU-STREAM-TABLE.md) | rung 2 — ∀-StreamID stream-table default-deny |
| [`SMMU-TRANSLATION.md`](SMMU-TRANSLATION.md) | rung 3 — translation: one proven `p2m`, two consumers |
| [`SMMU-DEVICE-ASSIGNMENT.md`](SMMU-DEVICE-ASSIGNMENT.md) | rung 4a — device assignment in the model |
| [`SMMU-STREAM-DERIVATION.md`](SMMU-STREAM-DERIVATION.md) | rung 4b — the metal derives the stream table |
| [`SMMU-DEVICE-PATH-COMPOSITION.md`](SMMU-DEVICE-PATH-COMPOSITION.md) | the whole device path as **one theorem** — the arc's headline sentence |

## Interrupts and the vGIC

| document | what it establishes |
|---|---|
| [`VGIC-SPI-ROUTING.md`](VGIC-SPI-ROUTING.md) | ⑱-6 — the guest aims an interrupt and the hypervisor obeys |
| [`INTERRUPT-CONFINEMENT.md`](INTERRUPT-CONFINEMENT.md) | ⑱-7/⑱-8 — the peer probe, and the role that made the guard unnecessary |
| [`GICD-RES0-SURFACE.md`](GICD-RES0-SURFACE.md) | ⑲ — a conforming guest was being killed for a legal read |

## Platform and direction

| document | what it establishes |
|---|---|
| [`QEMU-AND-METAL.md`](QEMU-AND-METAL.md) | ★ **what testing against QEMU does and does not mean.** Read before trusting any "on the metal" claim |
| [`ROADMAP.md`](ROADMAP.md) | from a proven model toward a "slim Qubes" — where this is going |
| [`CONSUMER-CORTENFORGE.md`](CONSUMER-CORTENFORGE.md) | ⚠ **a requirements derivation, not a commitment** — what a named consumer would need, and the one place it **collides with the Tier-D precondition**. Read before reviving any rung parked "for want of a consumer" |
| [`MILESTONES.md`](MILESTONES.md) | ⛔ **a LOG, not status** — the append-only record, 23 entries from M1's toy hypercall to two Alpine kernels on EL2. Moved out of the root README, where it was 561 of 850 lines |

---

## What is deliberately NOT here

**The live position** — what `main` is at, what merged, what to do next — is not in `docs/`, and this
is not an oversight. A repository document stating the current state is a copy that goes stale
between commits; the state lives in the commit log and the CI runs, and the *next move* is a
judgement, not a document.

**The honest ledger** lives in the root [`README.md`](../README.md), beside the claims it qualifies —
a ledger of what is unproven, filed one directory away from the proof claims, is a ledger nobody
reads.
