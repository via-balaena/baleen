<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# M5 Arc 1 — the concurrent scheduler, live (two vCPUs time-slice on the metal)

*The first time more than one vCPU runs on the metal, and the first time hv-core's **scheduler**
drives real execution. Arc 0 proved isolation across time (a reborn slot inherits nothing); Arc 1
multiplexes the single physical CPU between two vCPUs under the proven scheduler, preserving each
vCPU's full context across the switch and enforcing the scheduler's two safety invariants —
pCPU-exclusivity and hard-affinity — on real hardware.*

## Scope — what Arc 1 is, and is not

- **Is:** a real per-vCPU **context switch** (`GuestContext`: `x0..x30` + `SP_EL1` + `ELR/SPSR` +
  `SCTLR_EL1`, saved/restored around each switch); the **`__enter_guest_ctx`** primitive (seed a
  vCPU's registers + system state and `eret` into it — the real "dispatch a vCPU" op); a **cooperative
  run-loop** where the EL2 metal drives hv-core's real `SchedAdmit`/`SchedRun`/`SchedPreempt`/
  `SchedOffline` (as the vCPUs' owning domain) and enacts the result; and the scheduler pillar's two
  **safety-invariant refusals** — `PcpuBusy` (exclusivity) and `NotAffine` (affinity).
- **Is not:** preemptive/timer-driven scheduling — cooperative only (a timer preempt needs the vGIC +
  an async IRQ path, a later arc; `inject_interrupt` stays deferred). Not **SMP** — one physical CPU,
  secondaries stay PSCI-parked, so the crate's single-CPU `Sync` assumptions hold; concurrency is
  *temporal* (interleaved), not simultaneous. hv-core models 2 pCPUs but only pCPU 0 is physically
  run, so exclusivity/affinity are witnessed by hv-core's *refusals*, not by parallel execution. Not
  inter-**domain** memory isolation under concurrency (both vCPUs share one domain's address space
  here) — that is the next arc (per-domain Stage-2 + distinct VMIDs). Refines — no new model invariant.

Verified scope (per the ledger in `docs/ROADMAP.md`): ***refines*** — the model→metal bridge for the
**scheduler** pillar (pCPU-exclusivity + affinity), the temporal-multiplexing complement of the
spatial isolation Arcs 4–5/0 cashed. QEMU is a **sound oracle** for everything Arc 1 touches (the
`eret`/context-restore and the register/sysreg state are exactly what TCG models faithfully). No
timing, memory-order, or DMA claim is made.

## The scheduler matrix (the deliverable)

Two vCPUs (A, B) of one domain, on one pCPU. The EL2 metal is the scheduler policy; hv-core enforces
the invariants. Driven entirely through the real `Hypervisor::dispatch`:

```
SchedAdmit A, SchedAdmit B          Offline → Runnable (both)
SchedRun A, pcpu 0                   Runnable → Running (A on the pCPU)
  witness (exclusivity):  SchedRun B, pcpu 0  → Err(PcpuBusy)   — the pCPU is occupied
  witness (affinity):     SchedSetAffinity B = {pcpu 1};
                          SchedRun B, pcpu 0  → Err(NotAffine)  — pCPU 0 excluded by the mask
  restore B's affinity, seed both contexts (distinct counter bases), enter A
loop (each cooperative yield):
  save cur's context; SchedPreempt(cur) [Running→Runnable]; SchedRun(other) [Runnable→Running];
  restore other's context; eret into other
each vCPU: counter++ across SCHED_YIELDS yields, then reports its counter
  witness (context fidelity):  A ends at base_A + N (0x104), B at base_B + N (0x204), 2N switches
```

The **un-forgeable** witness is the last line: each vCPU's counter is seeded to a *distinct base*
(A=0x100, B=0x200) and carried in a callee-saved register across the interleaving. Both ending at
their **own** base + N proves each vCPU's private register state survived every context switch **and**
that the two contexts never crossed — a leak would land a counter in the wrong hundreds. The metal
also cross-checks each vCPU's self-reported id (a seeded register) against the slot it switched to, so
the intended context is the one that ran.

## The two safety-invariant refusals (the sched pillar, cashed)

The scheduler's safety content is two invariants (`docs/` + hv-core `sched.rs`): **pCPU-exclusivity**
(a physical CPU runs at most one vCPU) and **hard-affinity** (a `Running` vCPU is on a pCPU in its
mask). Arc 1 witnesses both as hv-core *refusals* on the metal:

- **Exclusivity:** with A `Running` on pCPU 0, `SchedRun(B, pcpu 0)` is refused `PcpuBusy` — the metal
  can never place two vCPUs on the one CPU, exactly as the model forbids.
- **Affinity:** with B's mask narrowed to exclude pCPU 0, `SchedRun(B, pcpu 0)` is refused
  `NotAffine`. The metal pins the witness to the *specific* error (not any `Err`), so a refusal for
  an incidental reason cannot pass for it (design-lesson #28(d)).

## The context switch — how it reuses the trampoline

The Arc-4 vector trampoline already saves `x0..x30` to an on-stack `GuestFrame` on every trap and
restores them before `eret`. A context switch rides that: `handle_yield` copies the frame's GPRs (plus
the system state `read_sysctx` reads) into `VCPU_CTX[cur]`, then loads `VCPU_CTX[other]` into the frame
(and `write_sysctx`), so the trampoline's existing `ldp`+`eret` resumes the *other* vCPU. Only a
vCPU's **first** dispatch needs `__enter_guest_ctx` (there is no trap frame yet), which loads a seeded
`GuestContext` into the real registers and `eret`s — this is what lets the metal give each vCPU its own
private initial register state. `SP_EL2` is reset to the exception stack on every entry (as in Arc 0),
so each vCPU's traps land on a clean frame regardless of how deep the previous handler ran.

## Method — three-way convergence

1. **Spec-derived code** — the scheduler transitions are the proven hv-core ops (`SchedAdmit`/`Run`/
   `Preempt`/`Offline`/`SetAffinity`), driven verbatim; the context switch reuses the Arc-4 trampoline.
2. **The model's own refusals** — the exclusivity/affinity witnesses ARE hv-core refusing the illegal
   `SchedRun`; each marker prints only when the proven scheduler actually returns the specific error.
3. **Running QEMU** — the two vCPUs' counters end at their distinct bases + N, cross-checked against
   the metal's own switch count; a broken save/restore or a crossed context fails the matrix.

## The QEMU-vs-metal line

Faithful under QEMU (relied on): the `eret`/context restore and the register/sysreg state; the
scheduler refusals are pure model logic. Blind to timing and to true parallelism (there is one core;
SMP is out of scope). The single-CPU, interrupt-masked, non-nested execution model the whole crate
rests on is unchanged — Arc 1 adds no concurrency the `Sync` justifications don't already assume.

## The diamond review pass — verdict SOUND

Hardened by the established method (design-lesson #27(j)/#28(h)): three **spec-blind auditors** on
orthogonal axes + empirical **mutation testing**.

- **Auditor A — Rust/unsafe + context-switch asm.** Verified every hard-coded offset in
  `__enter_guest_ctx` against the `repr(C)` layout (size 280, no padding), the register-restore
  ordering (ctx pointer `x0` loaded last, no read-after-clobber), that `ELR/SPSR` set by `write_sysctx`
  survive to the trampoline's `eret`, no aliasing in the context seeding, and the full 8-yield
  interleaving + endgame (the last finisher hits `finish` before running the offlined peer). **SOUND.**
- **Auditor B — false-green / witness integrity.** Confirmed the counter/id/switch triple is
  un-forgeable (bases seeded in the *context*, not guest code; the id cross-check binds guest identity
  to metal slot; a single vCPU running twice is impossible), both refusal markers are strictly gated on
  the exact `SchedError` variant with loud-halt `other` arms, and no marker is unconditional.
  **NO FALSE-GREEN.**
- **Auditor C — model-refinement + composition.** Verified against the *actual* hv-core source that
  every transition is legal from the state hv-core is in, that `SchedSetAffinity` authority is held
  (dom0's `Control::Root` edge), that the fresh-Hypervisor rebuild composes with the lifecycle phase,
  and — the pivotal point — that hv-core's `run()` checks **affinity before pCPU-occupancy**, so the
  `NotAffine` witness fires for the right reason. **FAITHFUL / SOUND COMPOSITION.**

**Empirical mutation testing** — three perturbations that *should* break the scheduler, each confirmed
caught (the matrix FAILS / boot halts, `SCHEDULER TEST PASSED` never prints):

| mutation | perturbation | caught by |
|---|---|---|
| context cross-leak | `restore_context` always loads slot 0 | `vCPU id mismatch (metal slot=1, guest reported=0); halting` |
| exclusivity defeat | probe a *free* pCPU (so `SchedRun` succeeds) | `exclusivity BROKEN: got Ok(Done); halting` |
| affinity wrong-cause | don't narrow the mask (probe fails `PcpuBusy`) | `affinity BROKEN: got PcpuBusy not NotAffine; halting` |

**Three below-bar findings fixed** (none a soundness/false-green defect):

1. *(Auditor A)* Bound the `__enter_guest_ctx` asm offsets to the struct with compile-time
   `const _: () = assert!(offset_of!(GuestContext, …) == …)`, so a future field reorder can't silently
   desync the asm (the `const _` discipline, #14c).
2. *(Auditor A)* Documented the scope boundary that FP/SIMD (`v0..v31`) is not saved — sound for the
   integer-register-only scheduler guests, flagged so a future FP guest doesn't inherit a silent leak.
3. *(Auditor B)* Made the affinity probe **occupancy-independent**: it now narrows B to exclude a
   *free* pCPU and probes there, so `NotAffine` is the only possible refusal — the witness no longer
   depends on hv-core's affinity-vs-occupancy check order (it failed *safe* before, but is now robust
   to a future hv-core refactor).

## Verdict

**SOUND, no defect.** Arc 1 refines the hv-core scheduler onto the metal: two vCPUs time-slice under
the real scheduler, each vCPU's full context survives every switch (witnessed by distinct carried
counters), and the pillar's two safety invariants — exclusivity and affinity — are enforced by
hv-core's refusals on real hardware. First **temporal-multiplexing** content on the metal; the vCPU
run-loop the rest of M5 (virtio channels, the disposable/vault thesis) schedules its guests on.
