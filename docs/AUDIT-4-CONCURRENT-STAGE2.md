<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Architecture Audit #4 — the two-set Stage-2 emission (concurrent inter-domain isolation)

Audit #2 asked: when the metal translates ONE domain's proven `p2m` into AArch64 Stage-2, does the
table deny *exactly* what the model forbids? Audit #4 extends that question to **two domains live at
once**: does emitting each domain's Stage-2 into its **own table set with its own VMID** still
faithfully realize each domain's `p2m`, and is a context switch between them — installing the peer's
`VTTBR_EL2` with **no `tlbi`** — sound? M5 Arc 2 (`docs/ARC-2-M5-CONCURRENT-ISOLATION.md`) is the arc;
`hv-metal/src/stage2.rs`'s two-set refactor is the audited surface (it touches the Audit-#2 emission
code).

## The charter — no more, no less

The concurrent isolation claim is that, with two domains A and B time-slicing on one pCPU:

> Each domain's Stage-2 maps **exactly** the frames that domain owns as leaves (at their model
> permission), and **nothing** the other domain owns — so each domain reaches its own memory and
> **faults** on the other's; and switching between the two domains' address spaces with no TLB flush
> does not let one domain's translations alias the other's.

Audit #4 verifies this per dimension against the model, the AArch64 encodings, and QEMU, and closes
with empirical mutation testing.

## The refinement — per-domain sets, per-domain VMID

The Audit-#2 relation is unchanged per domain: `Stage-2(G)` maps `IPA(m) → PA(m)` iff `m` is a
leaf-mapped child of a table `G` owns, at that leaf's permission. Arc 2 adds the multiplicity:

- `build_stage2_from_p2m(hv, G, set)` emits `G`'s leaves into table `set` (of `NUM_STAGE2_SETS = 2`),
  and returns `VTTBR = L1(set) | (set_vmid(set) << 48)`, where `set_vmid(set) = set + 1`.
- The per-domain filter is `leaf && owner_of(parent) == G` — so set `s` contains a leaf iff its
  parent table is owned by the domain that `s` was built for. Two domains → two sets, each the faithful
  Audit-#2 image of its own `p2m`, in disjoint storage.
- The two domains' data frames are **distinct `Mfn`s**, and `frame_pa(m) = data_ram_start + m·4KiB` is
  injective in `m`, so distinct `Mfn` ⇒ distinct host PA. The domains are physically disjoint, not
  merely table-separated.

## The test configuration (driven through the real model)

`setup_concurrent_model` drives, through the real `Hypervisor::dispatch`:

- dom0 creates dom A (`ISO_DOM_A`, VMID 1, set 0) and dom B (`ISO_DOM_B`, VMID 2, set 1).
- Each domain allocates its own L1 page-table root (`F_A_ROOT`=Mfn 1 / `F_B_ROOT`=Mfn 3) and one
  writable data frame (`F_A_DATA`=Mfn 2 / `F_B_DATA`=Mfn 4), pins the root as `PtLevel::L1`, and links
  the data frame as a **writable leaf** at slot 0.

So dom A's `p2m` has one leaf edge `(F_A_ROOT → F_A_DATA, writable)`; dom B's has
`(F_B_ROOT → F_B_DATA, writable)`. Set 0 emits `L3[2]`; set 1 emits `L3[4]`. Each set's other data
slots stay zero (translation-fault holes).

## Per-dimension verdict — model vs. emitted table vs. QEMU

| Dimension | Model says | Emitted (per set) | QEMU witness | Verdict |
|---|---|---|---|---|
| **own frame reachable** | A owns Mfn 2 (leaf, writable) | set 0: `L3[2] = PA(2) \| RW\|XN` | A writes+reads its sentinel `0xA1A1` back | ✅ |
| **peer frame unreachable** | A does NOT own Mfn 4 | set 0: `L3[4] = 0` | A's read of `IPA(4)` → translation fault (DFSC=0x07) | ✅ |
| **symmetric (B)** | B owns Mfn 4, not Mfn 2 | set 1: `L3[4]` mapped, `L3[2] = 0` | B reads its `0xB2B2`; B's read of `IPA(2)` → translation fault | ✅ |
| **physical disjointness** | Mfn 2 ≠ Mfn 4 | `frame_pa(2) ≠ frame_pa(4)` (injective) | both frames keep their own sentinel after the peer ran | ✅ |
| **distinct VMID / no flush** | (silicon: VMID-tagged TLB) | `VTTBR` VMID field 1 vs 2; switch = `msr vttbr_el2; isb`, no `tlbi` | isolation holds with no flush; aliasing the VMIDs breaks it (mutation 4) | ✅ |
| **fault class** | absence of a leaf ⇒ address does not translate | zero L3 descriptor | **translation** (DFSC=0x07), a **read** (WnR=0) — not permission | ✅ |

The cross-probe fault is a **translation** fault (no leaf), distinct from Audit-#2's write-to-RO
**permission** fault — the class discriminator (design-lesson #27) holds here too, and the witness pins
it (`is_translation` + `!WnR`), not merely "some fault."

## The "no more, no less" analysis

- **No more.** Set `s` emits a leaf only when `owner_of(parent) == G_s`. A frame the domain does not own
  has no owned parent edge, so no descriptor — the hardware faults it. The two sets are disjoint
  storage, so building one domain's table cannot add a descriptor to the other's. (Mutations 1 and 3
  perturb exactly these two guarantees and are caught.)
- **No less.** Every leaf the domain *does* own is emitted at its model permission (writable → S2AP=RW),
  so an authorized access succeeds (the sentinel round-trips). (Mutation 2 — the switch failing to
  install the domain's own VTTBR — makes an owned access fault, and is caught.)
- **The switch preserves both.** `restore_context` installs the incoming domain's VMID-tagged `VTTBR`
  with no flush. Soundness rests on the VMID: a walk for VMID *v* never consumes a cached entry tagged
  *v′≠v*, so the two domains' TLB entries coexist without aliasing. This is the **inverse** of Arc 0's
  rebirth (same VMID reused ⇒ must flush, #28f); here distinct VMIDs ⇒ **must not** flush (a flush would
  be pure waste). The `isb` orders the `VTTBR` write before the trampoline's `eret`; no `dsb`/`tlbi` is
  needed because the tables were fully built (invalid→valid) before Stage-2 was ever enabled and are
  not modified on the switch.
- **The shared code image** (both sets identity-map the same guest-RAM host frames) is named
  infrastructure, not an isolation surface: both domains run one register-only program and never write
  it. The review pass hardened this from inspection-asserted to **hardware-enforced**: the image is
  mapped **read-only + executable** (`desc::BLOCK_ROX`), so a store there faults loudly (an abort
  outside the data window halts in `record_data_abort`) rather than silently cross-corrupting. So the
  code plane is read-only-shared and the data plane is fully isolated. A private RW code+stack image
  per domain is the real-Linux capstone arc; deferred, not swept.

## Mutation testing — empirical break-class coverage

Each mutation perturbs the mechanism in a way that *should* break isolation; the boot-test matrix must
catch it (the `CONCURRENT ISOLATION TEST PASSED` marker must NOT print). All run on QEMU `-cpu max`.

| # | Mutation | Expected | Observed | Caught? |
|---|---|---|---|---|
| 1 | **alias the table storage** — `build` ignores `set`, always uses set 0 | building B overwrites A's set → A can't reach its own frame | `no_corruption=false a_denied=false a_rb=0x0` | ✅ |
| 2 | **drop the VTTBR swap** — `set_vttbr_no_flush` is a no-op | the switched-in domain runs with the peer's address space → its own access faults | `no_corruption=false b_denied=false b_rb=0x0` | ✅ |
| 3 | **map the peer's frame** — drop the `owner_of` filter, each set maps all leaves | each domain's Stage-2 maps the peer's frame → cross-probe succeeds | `a_denied=false b_denied=false` (no faults; `no_corruption=true` alone insufficient) | ✅ |
| 4 | **alias the VMIDs** — `set_vmid` returns 1 for both sets | shared VMID + no flush → stale-TLB alias | `a_denied=false b_denied=false a_dfsc=0x00 b_dfsc=0x00` | ✅ |

**Mutation 4 is the notable one.** Design-lesson #28f had assumed TLB retention is TCG-invisible. It is
not, for this QEMU: with a shared VMID and no flush, the switched-in domain's cross-probe **hits the
peer's stale VMID-1 TLB entry** and does not fault. Because the fault is table-guaranteed regardless of
the TLB (set 1 has no leaf at `IPA(2)`), a *missing* fault proves a stale hit occurred — so TCG here
**does** model VMID-tagged Stage-2 TLB retention, and the distinct-VMID / no-flush property is
**empirically witnessed**, not merely reasoned. Mutation 3's `no_corruption=true` datapoint also earns
its keep: it shows the no-corruption positive alone is *insufficient* for isolation (distinct PA keeps
both sentinels intact even under cross-access) — the **fault** witness is what actually catches a
mapping leak.

Real silicon remains the authority (TCG TLB fidelity is version/config-dependent), so the VMID property
stays under regression watch; but on this QEMU it is a live, caught witness, and this suggests the
Arc-0 rebirth `tlbi` (#28f) is similarly re-testable — flagged for a future re-examination.

## Method — three-way convergence

Spec-derived code + independent re-derivation (the AArch64 VTTBR/VMID/S2AP encodings and the per-domain
`p2m` → reachability refinement) + a live QEMU boot, all agreeing, plus the four-mutation empirical
pass. The diamond review pass adds three spec-blind auditors on orthogonal axes (unsafe/asm soundness;
false-green / witness integrity; model-refinement vs the actual hv-core source).

## Diamond review pass — auditor findings

Three spec-blind auditors on orthogonal axes, each re-deriving independently (the Arm ARM; the actual
hv-core source; the witness logic). **All three: no soundness bug on their axis.** Four below-bar
findings, all folded in:

1. **Unsafe / inline-asm (auditor 1) — SOUND.** Confirmed `set_vttbr_no_flush`'s `msr; isb` is correct
   AArch64 and the `dsb`/`tlbi` are genuinely *not* needed at the switch (distinct VMIDs; the
   switched-in domain's first access reads descriptors already published by the single `dsb ish` in
   `enable_stage2`, which runs *after both* sets are built). All unsafe blocks, the `repr(C)` offset
   asserts, and the register-only guest's seeding/fault-resume are sound. VMID reuse *across phases* is
   correctly flushed (`enable_stage2`'s VMID-scoped `tlbi`), while the no-flush path is used only
   *between* two stable distinct VMIDs within a phase. **Below-bar (folded):** the SAFETY comment
   claiming "one-time init before Stage-2 enabled" was factually stale (called once per phase, Stage-2
   already enabled in phases 3-4) → corrected to the real justification (rewritten at EL2 with no
   concurrent walker; re-fenced by `enable_stage2`). The two latent invariants — the clear loop must
   cover full model *capacity* (`frame_count()`, not a live count), and every no-flush-reachable set
   must be built before the covering `dsb` — are now pinned in comments.
2. **False-green / witness integrity (auditor 2) — TIGHT.** Confirmed the negative scoring cannot
   mis-score a non-fault (DFSC=0 rejected by `is_translation`), no A/B frame-index confusion, the HV
   read-back is a genuine Stage-2-bypassing witness, the guest read-back is a real memory round-trip
   (not a register echo), both domains provably run to completion (guarded by `ISO_DONE` + the id
   cross-check), and the phase-boundary state resets hold. **Below-bar (folded):** a single negative
   witness (`a_denied`) is not independent of the peer's own-frame health (its index is also where the
   peer writes) — it is load-bearing *only in conjunction* with `no_corruption`. The `PASSED`
   conjunction already makes it genuine; a comment now records exactly why.
3. **Model-refinement vs actual hv-core (auditor 3) — FAITHFUL.** Drove every metal claim back to the
   real `p2m`/`sched`/`dispatch` source: the per-domain `owner_of(parent)` filter separates the two
   domains' leaves exactly (no leak, no miss); a foreign leaf is grant-authorized by construction; the
   pinned root is correctly non-leaf (write-xor-pagetable); `frame_pa` injectivity + the 2 MiB linker
   window give real physical disjointness; the whole-system pCPU-exclusivity model genuinely supports
   two-domain contention (the `PcpuBusy` witness hits the modeled refusal); and dispatching sched ops
   "as the owning domain" matches the model's `dom`-is-owner semantics, the cross-domain preempt/run
   sequence staying inside the invariant. **Below-bar (folded):** the shared code image was RWX (a
   real, if inert, cross-domain write channel the corruption check was blind to) → hardened to **RO+X**
   (see above), plus the stale module-doc "private RAM" line corrected.

Own re-read + the four-mutation empirical pass corroborate. Every fold is documentation or a
*strengthening* (RO+X); no behavioural change to the isolation logic. Post-fix: metal-lint clean, the
full boot sequence (both configs) green — the RO+X image change is behaviour-neutral for the
register-only guests (none write their image).

## Verdict

**SOUND — no defect.** Two mutually-distrusting domains run concurrently on the metal, each isolated in
its own VMID-tagged Stage-2 with **no flush** between them: each reaches exactly its own memory and is
faulted (translation) on the peer's, with no cross-corruption, driven end-to-end through the proven
`hv-core` transitions and the Audit-#2 emission generalized to two disjoint sets. Three spec-blind
auditors on orthogonal axes converged SOUND; four mutations (storage-alias, drop-swap, map-peer,
**VMID-alias**) are all empirically caught — and the VMID-alias catch shows the distinct-VMID / no-flush
property is *witnessed* under this QEMU, not merely reasoned. Below-bar findings folded (RO+X image
hardening, three comment/doc corrections). The isolation thesis — spatial and temporal at once — holds
on real AArch64 Stage-2 hardware (as modeled by QEMU).
