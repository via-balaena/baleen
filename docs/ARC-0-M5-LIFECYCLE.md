<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# M5 Arc 0 — the lifecycle, live (a reborn slot inherits nothing)

*The first time a domain is **destroyed and reborn on the metal**, and the isolation the proof
guarantees across that boundary is witnessed by real hardware. Arc 5 proved a live guest is isolated
in space (real Stage-2 from the proven `p2m` faults an unauthorized access). Arc 0 of M5 proves the
guest is isolated across **time**: dom0 destroys it, reborns a fresh domain in the same slot, and the
reborn tenant provably inherits **no authority** from the domain that died there — it cannot reach a
frame its predecessor had been granted, and the hardware faults its attempt. This is the
`hv-core` lifecycle (`DeadDomainNotClean`, `DeadDomainReferenced`, ID-reuse — design-lessons #10/#15)
cashed onto the metal.*

## Scope — what Arc 0 is, and is not

- **Is:** the genuinely-new metal capability M5 needs — a **re-enterable guest run loop**
  (the phase-1 terminal handler drives phase 2 and re-`eret`s a second incarnation, resetting `SP_EL2`
  to the exception stack and clearing the re-entry guard rather than parking); **`DomainDestroy`
  driven on the metal** through the real `Hypervisor::dispatch` (the proven teardown, including
  `revoke_grants_to` sweeping the peer's inbound grant); **rebirth** (`DomainCreate`) into the same
  slot; and **Stage-2 re-emission** for the reborn domain from its fresh `p2m`. The lifecycle
  authorize/deny matrix is witnessed **in one boot**, all through proven transitions.
- **Is not:** any new *model* content — Arc 0 refines the existing lifecycle proofs onto hardware; it
  adds no `hv-core` invariant (`hv-core`/`hv-hal` are untouched). It is not virtio, not a real Linux
  guest, and not the control-domain-as-a-guest (dom0 acts as the control domain from EL2 here). Those
  are later M5 arcs.

Verified scope (per the ledger in `docs/ROADMAP.md`): ***refines*** — the model→metal bridge for
**lifecycle** isolation, the temporal complement of Arc 5's spatial bridge. QEMU is a **sound oracle**
for everything Arc 0 touches: Stage-2 translation/fault semantics (the reborn probe faults exactly as
Arc 5's probes did) and the exception/`eret` re-entry. No timing, memory-order, or DMA claim is made.

## The lifecycle matrix (the deliverable)

Phase 1 is the **unchanged Arc-5 negative-isolation test** — the positive baseline and a regression:
guest `G` (slot 1) lives behind real Stage-2, reaches its own writable/read-only frames and the one
frame peer `P` granted it, and is faulted on everything else. Only when that whole matrix passes does
phase 2 run (a broken baseline parks; we do not build a lifecycle claim on a broken foundation).

Phase 2 — driven entirely through `Hypervisor::dispatch` on the same proven brain:

```
DomainDestroy{target: G}   → proven teardown: releases G's frames, sweeps P's grant to G
  witness (model):   G is Dead and owns none of F_ROOT/F_RW/F_RO      → "clean shell"
DomainCreate{target: G}    → reborn G′ in the SAME slot
  G′ allocates a fresh root + writable frame, pins, links its own frame → fresh isolated space
  witness (seam):    G′ P2mLink of F_FGRANT (P's ex-granted frame) is REFUSED (no grant)
                     → "reborn slot could NOT link the destroyed grant"
re-emit Stage-2(G′), re-enter the phase-2 guest:
  positive:          G′ writes+reads its own fresh frame (0xcafe)      → succeeds
  negative:          G′ probes F_FGRANT → TRANSLATION fault (DFSC=0x07) → no descriptor exists
                     → "a reborn slot inherits nothing (destroyed grant not re-reachable)"
```

The **un-forgeable** witness is the last line: `F_FGRANT` is `P`'s frame; the *only* way any tenant of
slot `G` could reach it is a grant from `P`, and `P` granted it to the **dead** incarnation. Had the
teardown sweep (design-lesson #15's inbound-reference clearing) not fired, a naive "grant names a
slot id" hypervisor would let `G′` inherit it — a confused deputy reaching `P`'s memory. The proven
`hv-core` revokes it at teardown, so the model refuses `G′`'s link and the hardware faults `G′`'s
probe. Two independent oracles (the model's seam refusal; the CPU's Stage-2 fault) agree.

## The confused-deputy defense, named

This is the concrete metal realization of the exact leak design-lesson #15 closed in the model: two
inbound references (a grant `{grantor: P, grantee: G}`; a half-open port awaiting `G`) survived
teardown and were silently inherited by a slot's reborn tenant. Arc 0 exercises the **grant** case
end-to-end on hardware. The port case is covered by the same `DomainDestroy` sweep
(`clear_unbound_into`) and the same mint gate (`reject_dead_target`); an evtchn-over-the-metal witness
is a later arc's concern (no channel plumbing exists on the metal yet).

## Honest scope note — authority, not content

The proof guarantees a reborn slot inherits no **authority/reference** — no grant, no port, no owned
frame. It does **not** guarantee the *bytes* of a reused machine frame are scrubbed: `F_RW`'s host PA
is a pure function of its `Mfn`, so `G′` re-allocating `F_RW` reuses the same physical frame the dead
`G` wrote `0xbeef` into. **Content scrubbing on frame reuse is a metal allocator obligation**, not a
model one (the model abstracts machine frames as opaque `Mfn`s — the same fence that abstracts the
guest-physical→machine map and 512-slot tables, design-lesson #14e). Named-and-deferred to the arc
that stands up a real frame allocator. Here `G′` writes `0xcafe` before reading, so its own observed
content is fresh regardless — the positive witness is sound and the deferral is a decision on record,
not a gap.

## Method — three-way convergence

As with every metal arc (design-lessons #23–#27):

1. **Spec-derived code** — the lifecycle transitions are the proven `hv-core` ops (`DomainDestroy`,
   `DomainCreate`, `P2mAllocate/Pin/Link`), driven verbatim; Stage-2 re-emission reuses Arc-5's
   audited `build_stage2_from_p2m` unchanged (the leaf-reachability refinement, Audit #2).
2. **The model read back** — the clean-shell witness reads `is_live` + `owner_of` from the real brain
   after the destroy; the ID-reuse witness is the brain's *own* refusal of `G′`'s link. Neither is a
   printed assumption; each marker prints only when the proven model actually holds.
3. **Running QEMU** — the reborn probe faults with `DFSC=0x07` (translation) at `IPA=0x80004000`
   (`DATA_IPA_BASE + F_FGRANT*4KiB`), decoded through the same `ESR_EL2`/`HPFAR_EL2` path Arc 5 uses.
   A wrong outcome (the frame reachable, or a *permission* rather than *translation* fault) would fail
   the matrix; the PASSED marker is a witness produced by the hardware, not a bare line.

The re-entry mechanism was validated empirically: `SP_EL2` is reset to the exception stack on every
`enter_guest`, so the second incarnation's traps land on a clean frame; the `IN_GUEST_HANDLER` guard
is cleared before the re-`eret` (phase 2 diverges into `eret` rather than returning through the
trampoline), so `G′`'s first trap enters cleanly.

## The QEMU-vs-metal line

Faithful under QEMU (relied on): Stage-2 translation + fault class/`DFSC` for the reborn probe; the
`eret` re-entry and the exception model. The `dsb`/`tlbi vmalls12e1is`/`isb` in `enable_stage2` is
load-bearing on silicon (the re-emit changes the Stage-2 tables in place — the TLB must drop the dead
`G`'s stale `F_FGRANT` translation so `G′` actually faults) and invisible-but-correct under TCG, as in
Arcs 4–5. Blind to timing, weak-memory ordering, and DMA/SMMU — none of which Arc 0 tests. The
crate-wide EL2-MMU real-hardware gap (`docs/ARC-4-TRAP-AND-SERVICE.md`) is orthogonal and stays
named-and-deferred.

## Verdict

**SOUND, no defect.** Arc 0 refines the `hv-core` lifecycle onto the metal: a destroyed domain leaves
a clean shell, and a slot reborn in its place inherits no authority — witnessed by the model's own
teardown/refusal and, un-forgeably, by the hardware faulting the reborn tenant's reach for a frame it
was never granted. First **temporal** isolation content on the metal; the foundation the rest of M5
(concurrent guests, virtio channels, the disposable/vault thesis) builds on.
