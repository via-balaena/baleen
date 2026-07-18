<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Testing Baleen against QEMU — and what that does (and does not) mean

*Read this before running Baleen under an emulator and concluding anything about isolation. It is
the fidelity contract for emulated testing, in the same spirit as the abstraction notes in the
formal-methods docs (`docs/TIER-D-NONINTERFERENCE.md` §2.1, §5e–5f): name exactly what a tool can
and cannot see, so a green run is read for precisely what it is worth.*

## Where this sits

Baleen's isolation guarantees so far are **proofs about a model** — the pure `hv-core` brain. The
true-diamond program (`docs/TIER-B-CUTOFF.md`, `docs/TIER-C-SPIKE.md`,
`docs/TIER-D-NONINTERFERENCE.md`) proves, ∀-N, that the checked invariants hold *and* that they
collectively imply domain isolation, in both directions (integrity: no unauthorized domain can
*affect* another's observable state; confidentiality: no domain *learns* another's state
unauthorized). **Those proofs cover the model, not the metal.** Whether a running implementation on
real hardware enforces the model is a separate claim — and that is the gap emulated testing partly,
but only partly, closes.

QEMU is the natural first target (scriptable, fast, reproducible, and it models the AArch64
architecture faithfully at the *architectural* level). But an emulator is not silicon, and treating
"passes on QEMU" as "isolates on metal" would be exactly the kind of imprecise claim this project
otherwise avoids. This doc draws the line.

## What QEMU is faithful enough to trust

QEMU implements the ARMv8-A **architectural** semantics well: EL2/EL1/EL0, the exception model,
system registers, and — the part that matters most here — **Stage-2 translation and fault
semantics**. When a guest touches memory it is not permitted to, the architecturally-defined result
is a Stage-2 fault to EL2, and QEMU produces it faithfully.

That makes QEMU **sound for the single most valuable test**: the **model-refinement / negative
isolation test**. Drive a guest that deliberately tries to break isolation — touch another domain's
frame, use a revoked grant, walk into a foreign page table — and confirm that the *real Stage-2
tables the implementation generates from the model's `p2m`* actually fault it. This is the bridge
that makes the proof mean something about running code:

> the proof says *"the `p2m` enforces isolation"*; QEMU confirms *"the real page tables emitted from
> that `p2m` actually deny the access."*

QEMU will not mislead you about that — it is architectural functional behavior. For functional
bring-up and refinement (does trap-and-emulate work; does the ABI decode turn guest register state
into the right `HvCall`; does the generated Stage-2 mapping deny what the model says it should),
QEMU is the right tool and an honest one.

## What QEMU will mislead you about

An emulator — and QEMU under **TCG** (pure emulation) in particular — is functional, not
microarchitectural. It does **not** model:

1. **Timing / microarchitecture.** No caches, no TLB timing, no pipeline, no memory latency, no
   contention. This is the big one, and note that it is *the same covert channel the model already
   excludes* (the pCPU timing/availability channel, `TIER-D` §2.1). So it is a consistent blind
   spot on both sides: the proof does not cover timing isolation, and QEMU cannot test it. **A green
   QEMU run is zero evidence about cache/timing side-channels** (Spectre/Meltdown-class,
   cache-timing, scheduling covert channels).

2. **Weak memory ordering / missing barriers.** Real ARM reorders aggressively; a missing
   `DMB`/`DSB`/`ISB` manifests only under real microarchitectural reordering. QEMU's TCG has much
   stronger effective ordering and frequently will **not** expose the bug. This is the classic
   "worked in emulation, hung on silicon" — concurrency and barrier bugs pass QEMU and fail metal.

3. **DMA / SMMU (IOMMU) isolation.** The Stage-2 proof and its QEMU refinement cover **CPU-initiated**
   accesses. A device performing DMA can bypass Stage-2 entirely unless the SMMU is configured — a
   *separate* isolation mechanism that QEMU's `virt` machine barely stresses. DMA isolation is a
   place real hypervisor isolation genuinely breaks, and emulation gives false comfort. It is also a
   mechanism `hv-core` does not model at all yet.

4. **Errata and IMPLEMENTATION-DEFINED behavior.** QEMU implements one clean interpretation of the
   architecture; real SoCs carry silicon errata and IMPDEF corners (feature registers, cache line
   sizes, optional feature presence). Only real silicon settles these.

## A note specific to Apple-Silicon / EL2-under-QEMU

Baleen targets AArch64 **EL2**. If Baleen itself runs at EL2 on an Apple-Silicon host, it will
almost certainly run under QEMU **TCG (pure emulation)** rather than hardware-accelerated, because
the host hypervisor framework does not cleanly expose EL2 to guests (nested virtualization is the
limiting factor). TCG is the *least* faithful mode microarchitecturally — functional only. So in
that environment the timing / memory-ordering gap is **maximal, not incidental**: QEMU there is a
functional-correctness tool, full stop, and items (1)–(4) above must be validated later on real
ARM hardware with EL2 access.

## The discipline — how not to be misled

Same move that keeps the proofs honest — name the abstraction:

- **Use QEMU for functional refinement, and state in the test harness what it does *not* validate.**
  A one-line disclaimer on the emulated suite: *"validates functional isolation of CPU memory
  accesses; does not validate timing, memory-ordering, DMA, or errata."*
- **Keep the claim precise.** After a green QEMU run, the honest statement is *"functionally refines
  the proven model (CPU-access isolation)"* — **not** *"isolates on metal."* The delta between those
  is exactly items (1)–(4).
- **Sequence QEMU-first anyway.** The bugs QEMU *does* catch (functional logic errors in Stage-2
  generation, ABI decode, trap handling) are the ones hit first and most often, and iterating on
  silicon is slow. QEMU-first is correct; the only error is declaring victory there.
- **Plan a real-hardware phase for the rest.** Its specific job is the four things QEMU cannot see:
  weak-memory correctness, DMA/SMMU isolation, timing behavior, and errata. Some of those (timing
  side-channels, DMA) require *additional design work*, not just testing — constant-time discipline,
  SMMU configuration — because they are mechanisms the current model does not yet contain.

## The one-line summary

QEMU won't mislead you about **whether the isolation logic is functionally correct** — which is the
thing most worth checking next, so QEMU-first is right — but it gives **no** signal about timing,
memory-ordering, DMA, or errata. The honest post-QEMU claim is *"functionally refines the proven
model,"* and the gap to *"isolates on real metal"* is precisely those four things, which real
hardware (and, for side-channels and DMA, new design work) must close. Read a green QEMU run for
exactly that, and no more.
