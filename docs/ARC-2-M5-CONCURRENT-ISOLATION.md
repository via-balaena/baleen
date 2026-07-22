<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# M5 Arc 2 — concurrent inter-domain isolation, live (two domains, distinct VMIDs, no flush)

Arc 1 proved **temporal** multiplexing: two vCPUs of *one* domain time-slice on the single physical
CPU, switched by hv-core's real scheduler, each keeping its own register context. Arc 2 is its
**spatial** complement: two *domains* time-slice under that same scheduler, but now each runs in its
**own Stage-2** — a distinct table set, tagged with a distinct **VMID** — and each **faults on
hardware** when it touches the memory the *other* domain owns, **with no `tlbi` on the switch**.

This is the first time two mutually-distrusting address spaces coexist live on the metal. It refines
(no new hv-core invariant); it touches the Audit-#2 Stage-2 emission code, so it earns its own
**Architecture Audit #4** (`docs/AUDIT-4-CONCURRENT-STAGE2.md`).

## Scope — what Arc 2 is, and is not

- **Two domains, one vCPU each**, time-slicing on **one** physical CPU (2 pCPUs modeled, 1 run;
  secondaries PSCI-parked). **Temporal** concurrency between domains, **not SMP** — same physical-CPU
  scope as Arc 1.
- **Cooperative**, as Arc 1: each domain yields (`NR_YIELD`); no timer/GIC preemption yet (the vGIC
  arc). The switch machinery is unchanged from Arc 1 — Arc 2 only adds the **per-domain VTTBR swap**.
- **The isolation surface is the per-domain data frames.** Each domain owns a **distinct machine
  frame** (`Mfn`), and `frame_pa` is injective in `Mfn`, so the two domains' data live at **distinct
  host PA** — physically disjoint, not merely table-separated.
- **The two domains share their *code* image** (one register-only program, identity-mapped in both
  sets) as test infrastructure — they run identical code and never write it. It is mapped **read-only +
  executable**, so the shared image **cannot** be a cross-domain write channel: a store there faults
  loudly (hardware-enforced, not inspection-asserted). Inter-domain isolation is thus complete on the
  data plane and read-only-shared on the code plane; a private RW code+stack image per domain is the
  real-Linux capstone arc (deferred, named). *(RO+X hardening folded in from the review pass.)*
- **`hv-core` / `hv-hal` untouched.** The metal is scheduler *policy* + the Stage-2 refinement; hv-core
  is the mechanism. No new invariant — Arc 2 is strictly *more* isolated than Arc 1 (data now
  per-domain), realized entirely through the proven transitions and the audited emission.

## The concurrent-isolation matrix (the deliverable)

Two domains, **A** (VMID 1, set 0) and **B** (VMID 2, set 1), each owning one writable data frame
(`F_A_DATA` = Mfn 2 → host PA₂; `F_B_DATA` = Mfn 4 → host PA₄, distinct). Both run one shared program,
seeded per-domain with its own sentinel and two IPAs: `MINE` (its own frame) and `PEER` (the IPA the
*other* domain's frame lives at, which its Stage-2 does **not** map). The interleave:

1. **A** writes `SENTINEL_ISO_A` to `MINE` (authorized RW leaf), **yields**.
2. Switch to **B** (VTTBR → B's set, VMID 2, **no `tlbi`**). **B** writes `SENTINEL_ISO_B` to its own
   `MINE`, **yields**.
3. Switch back to **A**. **A** reads `MINE` back — still `SENTINEL_ISO_A` (B's run didn't corrupt it) —
   then probes `PEER` (B's frame IPA) → **translation fault** (A's Stage-2 has no leaf there). A
   reports its read-back and finishes; the terminal switches to **B**.
4. **B** reads its `MINE` back — still `SENTINEL_ISO_B` — probes `PEER` (A's frame IPA) → **translation
   fault**. B reports and finishes.

Three witnesses, all produced by the mechanism under test:

- **Concurrent isolation** — each domain's cross-probe faults (translation, a *read* → `WnR=0`). The
  fault **frame index** is the discriminator: a fault at `F_B_DATA` is A's cross-probe, at `F_A_DATA` is
  B's. Pinned to the *translation* class (no leaf), not permission (design-lesson #28d).
- **No cross-corruption** — each domain's guest read-back equals its own sentinel, **and** the
  hypervisor reads each frame back through the realized `GuestMemory` (distinct host PA, so the peer's
  run could not have touched it).
- **VMID-tagged / no-flush** — all of the above holds despite **no `tlbi`** between the two domains'
  runs.

The `CONCURRENT ISOLATION TEST PASSED` marker prints only when the whole matrix holds.

## Why no `tlbi` on the switch — and its honesty boundary

Switching the active Stage-2 between two domains needs no TLB flush **because** the two domains'
translations are tagged with **distinct VMIDs** (`set_vmid(set) = set + 1`): a walk for one domain's
VMID can never hit the other's cached entries, so the stale entries a switch leaves behind are inert,
not aliasing. This is the exact **inverse** of Arc 0's *rebirth*, which reuses a VMID for a different
tenant and therefore **must** `tlbi` (design-lesson #28f). Distinct VMIDs ⇒ no flush; reused VMID ⇒
flush.

**The empirical result (a correction to the #28f assumption).** Design-lesson #28f assumed TLB
retention is *TCG-invisible*. Arc 2's mutation testing shows otherwise for **this** QEMU/`-cpu max`:
aliasing the two VMIDs (both → VMID 1) while keeping everything else — distinct tables, distinct PA —
**is caught** (`docs/AUDIT-4-CONCURRENT-STAGE2.md`, mutation 4). With a shared VMID and no flush, the
switched-in domain's cross-probe **hits the peer's stale VMID-1 TLB entry** and does *not* fault — the
exact aliasing bug distinct VMIDs prevent. Because the fault is table-guaranteed regardless of the TLB,
a *missing* fault proves a stale hit occurred; so TCG here **does** model VMID-tagged Stage-2 TLB
retention, and the distinct-VMID / no-flush property is **empirically witnessed**, not merely reasoned.
Real silicon remains the ultimate authority (TCG TLB fidelity is version/config-dependent), so the
property stays under regression watch — but on this QEMU it is a live, caught witness. This suggests the
Arc-0 rebirth `tlbi` (#28f) is similarly re-testable; flagged for a future re-examination.

## How the switch reuses Arc 1's machinery

The context switch is unchanged from Arc 1 (the trap-trampoline frame carries the GPRs; `save_context`
/ `restore_context` move the GPRs + the sysregs the frame lacks). Arc 2 adds exactly one thing: a
per-slot `VcpuMeta { dom, vcpu, vttbr }`, and `restore_context` now also installs
`VCPU_META[vcpu].vttbr` via `set_vttbr_no_flush` (`msr vttbr_el2; isb` — **no `tlbi`**). For the
single-domain scheduler phase both slots carry the same `vttbr`, so the install is an **identity
write** — Arc 1's `SCHEDULER TEST` stays a byte-for-byte regression. The scheduler ops (`SchedPreempt`
/ `SchedRun` / `SchedOffline`) are now dispatched as each vCPU's **owning domain** (from `VcpuMeta`),
which is identical under Arc 1 and distinct-domain under Arc 2. One shared `retire_and_switch_to_peer`
tail serves both terminals so the retire→switch sequence can't drift.

Cross-domain pCPU exclusivity is witnessed directly: dom B's `SchedRun` onto the pCPU dom A occupies →
`PcpuBusy` — now genuinely *cross*-domain (two distinct domains contend for one physical CPU), a
stronger form of Arc 1's same-domain probe.

## The Stage-2 refactor (the Audit-#4 surface)

`stage2.rs` goes from one static table set to `NUM_STAGE2_SETS = 2` **per-domain** sets;
`build_stage2_from_p2m(hv, dom, set)` gains a `set` argument selecting which set to emit into (and thus
which VMID the returned VTTBR carries, `set + 1`). The sets are **disjoint storage**, so building one
domain's Stage-2 never touches another's — the two live simultaneously, distinguished by VTTBR alone.
All three single-domain callers (Arc 0/5 isolation + lifecycle, Arc 1 scheduler) pass `set 0` →
byte-identical to before (VMID 1, same storage).

The isolation falls straight out of the refinement, **no hand-built holes**: each set emits only leaves
whose parent that domain owns (`owner_of(parent) == guest_dom`). Set 0 emits A's leaf (`L3[2]`); set 1
emits B's (`L3[4]`). A's Stage-2 has *nothing* at `L3[4]`, so A's probe of B's frame IPA walks to a
zero descriptor → translation fault. Pure per-domain `p2m` → per-domain Stage-2.

## Method — three-way convergence

As every metal arc (design-lesson #23): the spec-derived code, a spec-blind re-derivation (the AArch64
VMID/VTTBR encodings + the per-domain refinement, in Audit #4), and a live QEMU boot all agree. Every
marker is a witness produced *by* the mechanism, not a progress print — the `PASSED` line prints only
when the read-backs match **and** both cross-probes faulted with the right class and direction.

## Files

- `hv-metal/src/stage2.rs` — two per-domain table sets; `build_stage2_from_p2m(hv, dom, set)`;
  `set_vmid(set) = set + 1`; `NUM_STAGE2_SETS`.
- `hv-metal/src/guest.rs` — `VcpuMeta` + `set_vttbr_no_flush` (per-domain VTTBR swap, no flush); the
  unified switch (`restore_context` installs VTTBR; the sched ops key on `VcpuMeta`); the shared
  `guest4` probe program; `setup_concurrent_model`; `begin_concurrent_iso_phase4`; `handle_iso_final`;
  `finish_concurrent_iso_test`; chained off the phase-3 terminal.
- `hv-metal/boot-test.sh` — the four new markers (cross-domain exclusivity + the three matrix
  witnesses), both build configs.
- `docs/AUDIT-4-CONCURRENT-STAGE2.md` — Architecture Audit #4 (the two-set emission refinement).

## Verdict

Two mutually-distrusting domains run concurrently on the metal, each isolated in its own VMID-tagged
Stage-2 with no flush between them — each reaches its own memory and is faulted on the peer's, with no
cross-corruption. The isolation thesis, spatial and temporal at once. See Audit #4 for the
per-dimension soundness verdict and the diamond review pass.
