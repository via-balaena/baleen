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

3. **DMA / SMMU (IOMMU) isolation — CORRECTED 2026-07-28, and the correction matters.** The Stage-2
   proof and its QEMU refinement cover **CPU-initiated** accesses; a device performing DMA bypasses
   Stage-2 entirely unless the SMMU is configured, and it is a *separate* isolation mechanism
   `hv-core` does not model. What this section used to say beyond that — that QEMU "barely stresses"
   the SMMU and gives only false comfort — **was wrong, and it went unchallenged for several arcs.**
   QEMU `virt` with `iommu=smmuv3` instantiates a real SMMUv3 at `0x9050000` that is EL2-reachable,
   coexists with `virtualization=on`, and **implements stage-2** (`IDR0 = 0x0d44101b`, `S1P|S2P`, read
   first-hand from the device). Three rungs of genuine DMA isolation are now witnessed on it: rung 1
   (PR #91) closes the pre-enable `GBPA` bypass window; rung 2 (PR #92) installs an all-deny stream
   table with a five-phase witness in which a real bus master's DMA gets *through* a
   deliberately-configured STE and is *aborted* without one (`docs/SMMU-STREAM-TABLE.md`); and rung 3
   **translates** — the device is bound to a domain's own `p2m`-derived Stage-2 tables, and QEMU
   models the walk faithfully enough that the DMA lands at the address the *table* names rather than
   the one the device issued, faults `F_TRANSLATION` on an IPA the domain does not own, and faults
   `F_PERMISSION` on a leaf the emitter marked read-only (`docs/SMMU-TRANSLATION.md`).

   The honest residue is narrower than the old text and worth stating precisely: QEMU is a
   **functional** model of the SMMU, so it validates the *configuration logic* (which StreamID gets
   which entry, pointing at which tables, in which order, with which invalidation) and not the
   silicon. It is also *more forgiving* in places — it aligns `STRTAB_BASE` down to the table size
   itself, so a mis-aligned base that would be truncated to a different table on hardware works fine
   here. That is why the architectural alignment is pinned by a compile-time assertion rather than
   trusted to the boot test. Two rung-3 mutations likewise produced **no** behavioural change, and are
   recorded as platform findings rather than as passing checks: a wrong `STE.S2VMID` (VMID tagging is
   not exhibited by cold walks) and a removed `CMD_TLBI_NSNH_ALL`. "QEMU cannot validate SMMU
   isolation at all" is not a claim this project can make any more; "a green QEMU run witnesses the
   SMMU's *VMID tagging* or its *TLB maintenance*" is not one it can make either.

4. **Errata and IMPLEMENTATION-DEFINED behavior.** QEMU implements one clean interpretation of the
   architecture; real SoCs carry silicon errata and IMPDEF corners (feature registers, cache line
   sizes, optional feature presence). Only real silicon settles these.

5. ★ **PROHIBITIONS THE ARCHITECTURE STATES AND QEMU DOES NOT ENFORCE — added 2026-08-07, and this
   is a different and nastier category than 1–4.** Items 1–4 are things QEMU cannot *measure*. These
   are things QEMU permits that hardware forbids, so **a wrong implementation passes here**, and no
   amount of green makes it right. Three found in one day, each while building something else:

   ⚠ **Read the two columns differently.** *"QEMU"* is **measured on this machine**. *"expected of
   hardware"* is **asserted from the architecture and NOT verified against a primary source in the
   session that wrote this row** — it is the reason each divergence matters, not itself a
   measurement. Marked because a doc about the limits of evidence is the worst possible place to
   blur that line, and the temptation to state both halves in the same voice is exactly the failure
   this whole section is about.

   | expected of hardware (asserted) | QEMU (MEASURED) | consequence |
   |---|---|---|
   | `SCTLR_EL2` has **RES1** bits a conforming implementation reads back as 1 | reads a flat **`0x0`** | a full-register write of a hand-built value would clear them and **passes here**. Setting `SCTLR_EL2.M` is a **read-modify-write** (`hv-metal/src/mmu.rs`) — which is correct practice whether or not the RES1 claim holds, so the guard does not rest on the unverified half |
   | **instruction fetch from Device memory** is prohibited independently of `XN` | **permitted** — clear `XN` on a `Device-nGnRnE` page and the jump succeeds | the `xn-probe` witness isolates `XN` *here*; if the assertion holds, it would not on silicon, where the property is doubly held. **The witness is strongest exactly where the model is weakest** |
   | the **SMMU caches** translations and configuration, so invalidation is load-bearing | models **no SMMU caching at all** (long-established in this repo) | "the TLBI made no difference" and "there is nothing to invalidate" are **the same observation**. This is why honest-ledger 2(d) was unwitnessable here and needed Arm's AEM (`fvp-probe`), where both were then measured directly |

   ★ **The reusable form: when a remove-the-fix probe will not go red, ask whether the PLATFORM can
   express the failure at all before concluding the guard is inert.** SMMU rungs 3 and 4b both hit
   this and correctly recorded "reasoned, not witnessed" rather than deleting the guard; the third
   row above is what finally settled which of the two candidate explanations was true.

   ⚠ **None of these is a QEMU bug** — an emulator is entitled to be permissive where the
   architecture forbids. They are limits on what a green run means.

## A note specific to Apple-Silicon / EL2-under-QEMU

Baleen targets AArch64 **EL2**. If Baleen itself runs at EL2 on an Apple-Silicon host, it will
almost certainly run under QEMU **TCG (pure emulation)** rather than hardware-accelerated, because
the host hypervisor framework does not cleanly expose EL2 to guests (nested virtualization is the
limiting factor). TCG is the *least* faithful mode microarchitecturally — functional only. So in
that environment the timing / memory-ordering gap is **maximal, not incidental**: QEMU there is a
functional-correctness tool, full stop, and items (1)–(4) above must be validated later on real
ARM hardware with EL2 access.

**A concrete instance of items (2) and (4), named by the M4 Arc-4 review pass — the EL2-MMU gap.**
Through M4 the hypervisor runs with its *own* stage-1 MMU off (`SCTLR_EL2.M=0`), so on real silicon
every EL2 data access is Device-nGnRnE. That makes the hypervisor's **atomics** (spinless
`compare_exchange` in the allocator, the guest handler's re-entry flag) architecturally
**UNPREDICTABLE** — `LDXR/STXR` on Device memory typically livelock — and leaves **caches unmanaged**
(freshly-written guest code vs. the I-cache; a cacheable Stage-2 walker vs. uncached descriptor
writes). Both are **completely invisible under TCG** and do not affect the proof; they are the
distance between a green QEMU boot and a real-metal run. The fix is a named prerequisite arc for the
first real-hardware run — an EL2 stage-1 Normal-cacheable identity map + `SCTLR_EL2.M/C/I` + boot
cache-invalidation — deferred because its core payoff can only be *validated* on real EL2 silicon
(see `docs/ARC-4-TRAP-AND-SERVICE.md`, "Real-hardware readiness"). Read a green QEMU boot as
functional evidence only, exactly as this doc says.

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
- **Plan a real-hardware phase for the rest.** Its specific job is weak-memory correctness, timing
  behavior, errata — and the *silicon* half of DMA isolation, which is a narrower job than this
  document used to claim (see item 3: the SMMU **configuration** logic is validatable here, and is
  being validated). Timing side-channels still require *additional design work* rather than testing,
  because they are mechanisms the current model does not contain.

## The one-line summary

QEMU won't mislead you about **whether the isolation logic is functionally correct** — which is the
thing most worth checking next, so QEMU-first is right — but it gives **no** signal about timing,
memory-ordering, DMA, or errata. The honest post-QEMU claim is *"functionally refines the proven
model,"* and the gap to *"isolates on real metal"* is precisely those four things, which real
hardware (and, for side-channels and DMA, new design work) must close. Read a green QEMU run for
exactly that, and no more.
