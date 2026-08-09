<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# M4 Arc 4 — trap-and-service (the proof touches a guest)

*The first time the ∀-N `hv-core` brain services a hypercall issued by a **real EL1 guest** on
(emulated) hardware. Arc 3 ran the brain at EL2 with a synthetic, EL2-issued `HvCall`; Arc 4 stands
up an actual guest, traps its `HVC`, decodes it through `hv-core`'s ABI seam, routes it through the
**actual** `Hypervisor::dispatch`, hands the result back, and the guest observes it. This records
what Arc 4 built, the per-layer verdict, the three-way convergence behind it, and the M4 HAL ledger.*

## Scope — what Arc 4 is, and is not

- **Is:** EL1 entry (`eret` with `SPSR_EL2`/`ELR_EL2`); a **minimal Stage-2** (`HCR_EL2.VM=1` + a
  single 2 MiB identity block mapping just the guest's RAM); the `HVC` synchronous trap from a lower
  EL (`EC=0x16`, vector slot 8); a GPR **save/restore frame** on a **dedicated exception stack** with
  a **re-entry guard** (the items Arc 2's *diagnostic* handler deferred — it halted and never
  resumed, so it needed none); decode → dispatch → result → `eret` to resume; and a witness produced
  *by the guest* that the round trip reached its register file.
- **Is not:** any **isolation content**. The Stage-2 map is *just enough to run the guest*; it does
  not come from the model's `p2m`, and there is **no negative-isolation test**. Translating the
  proven `p2m` into faithful AArch64 Stage-2 descriptors and faulting a guest that touches
  unauthorized memory — with **Architecture Audit #2** — is **Arc 5**.

Verified scope (per the ledger in `docs/ROADMAP.md`): ***refines*** — Arc 4 realizes the model's
southbound dispatch for a real guest; it proves no new property. QEMU is a **sound third oracle** for
everything Arc 4 touches (the ARMv8-A exception model, `eret`, and the `HVC` trap are exactly what
QEMU is architecturally faithful about; `docs/QEMU-AND-METAL.md`). No isolation, timing, memory-order,
or DMA claim is made or implied by a green boot.

## The round trip (the deliverable)

A trivial guest — a `.rodata` template the hypervisor copies into guest RAM and `eret`s to — does:

```
grant 100  → CreditGrant(100) serviced by Hypervisor::dispatch → x0 = 100
spend  30  → CreditSpend(30)  serviced by Hypervisor::dispatch → x0 = 70   (the first resume worked)
report 70  → guest echoes the balance it received; the hypervisor asserts it equals the 70 it
             last returned, and prints the witness
```

`x0` carries the hypercall number, `x1` the argument (the `RawHypercall` convention); the result
returns in `x0`. **70 is no call's input** — echoing it proves the guest observed the *serviced*
result, not a value passed through — and it takes **two** resume cycles to reach, so the round trip
witnesses the save/restore frame + `eret` genuinely resuming the guest across multiple traps. The
CI boot-test asserts every step (`hv-metal/boot-test.sh`); under `--features selftest` it additionally
hard-asserts the round-trip equality and then chains the Arc-2 deliberate-`BRK` fault-catch, so every
prior arc's witness still fires in the same boot.

## The decode seam

The guest presents raw registers. They flow through `hv_core::Hypercall::decode` — the same pure,
fuzzed `RawHypercall`→typed decoder `hv-fuzz` hammers — and the typed `Hypercall` is mapped to an
`HvCall` and routed through `Hypervisor::dispatch`, the proven integrated brain. The `Hypercall`→
`HvCall` map is **stand-in personality glue**: at M5 the `baleen-xenabi` personality owns the whole
wire-format→`HvCall` decode and the hand-mapping goes away. The core never sees a register; the metal
never sees an operation's meaning — the split the fence draws.

## Method — three-way convergence (design-lessons #23, #24)

The register-level claims were established three independent ways, and they agree:

1. **Spec-derived code** — the exception/`eret` contract and the Stage-2 encodings were read from the
   Arm ARM and encoded in `hv-metal/src/guest.rs` / `exceptions.rs`.
2. **A spec-blind auditor** — an independent re-derivation from the Arm ARM, with **no sight of the
   code**, of: the guest-`HVC` vector slot (**8**, lower-EL/AArch64/sync, offset 0x400) and class
   (**`EC=0x16`**); that `ELR_EL2` for `HVC` points *after* the instruction (so the handler does not
   advance it, and `eret` resumes past the `HVC`); `SPSR_EL2` for EL1h + DAIF-masked (**0x3C5**);
   that `SP_EL1` is banked and only `x0..x30` need saving for a straight-line masked handler;
   `HCR_EL2` bits (VM=0, RW=31, TGE=27 must be 0, HCD=29 must be 0 to enable `HVC`); the full
   **`VTCR_EL2` = 0x8002_3559** (4 KiB granule, 39-bit IPA/T0SZ=25, start level 1/SL0=1, WBWA IS
   walks, 40-bit PS, RES1 bit 31 — a single 512-entry L1, no concatenation); `VTTBR_EL2` (VMID in
   bits [55:48], 4 KiB-aligned base); the Stage-2 **table descriptor low bits `0x3`** and **2 MiB
   block low-attribute bits `0x7FD`** (block, Normal WB, S2AP=RW, SH=IS, AF=1, XN=0/executable); and
   the **`dsb ish; tlbi vmalls12e1is; dsb ish; isb`** maintenance sequence. **Every value converged
   with the code.** The auditor surfaced one refinement — also clear `SCTLR_EL1.A` (alignment check,
   bit 1) alongside M/C/SA/SA0/I when forcing the guest's Stage-1 off — which was folded in. It also
   confirmed the load-bearing silicon point that the Stage-2 block must be **Normal, not Device**,
   because an instruction fetch from Device memory faults on real hardware though TCG tolerates it.
3. **The running emulator** — QEMU boots the image and prints the guest entering EL1, both
   hypercalls serviced (`nr=0 arg=100 → 100`, `nr=1 arg=30 → 70`), and the guest observing `70` on
   the round trip. A wrong Stage-2 or `eret` would mean the guest never fetches or never resumes and
   no marker appears — so a green run is real functional evidence.

## The QEMU-vs-metal line, drawn per mechanism

- **`eret` / exception entry / `HVC` trap** — architecturally faithful under QEMU; a sound oracle.
- **`ELR_EL2` for `HVC`** — points to the instruction *after* the `HVC` (unlike an abort); true on
  both, so the handler never advances it and `eret` resumes past the `HVC`.
- **Stage-2 TLB maintenance + barriers** — `dsb`/`tlbi`/`isb` after programming `VTTBR_EL2`/
  `VTCR_EL2`/`HCR_EL2.VM` are load-bearing on silicon (reset TLB state is UNKNOWN; the `isb` orders
  the new regime before `eret`) and invisible-but-harmless under TCG. Emitted anyway.
- **Guest Stage-1 off** — with `SCTLR_EL1.M=0` and `HCR_EL2.DC=0`, data accesses default to Device
  and instruction fetches to Normal; the trivial guest does no data access, and it fetches from a
  **Normal, non-execute-never** Stage-2 block (executable on both QEMU and silicon). `SCTLR_EL1`
  enables are forced off by read-modify-write because its reset value is architecturally UNKNOWN on
  real hardware (QEMU gives a clean one).

## The M4 HAL ledger — `hv-hal` traits, Arc 4 status

Continuing the M3 ledger (`docs/AUDIT-1-HAL-FENCE.md`). No trait *signature* changed — the fence
stays architecture-neutral (Audit #1) — this records which are realized on ARM as of Arc 4.

| trait / method | neutral? | ARM metal (Arc 4) | fidelity check | verified scope |
|---|---|---|---|---|
| `TimeSource::now` | ✅ | ✅ realized (Arc 3, `CNTPCT_EL0`) | `witness_advance` every boot | *refines* — honored |
| `VcpuOps::set_entry` | ✅ | ✅ **realized this arc** — writes `ELR_EL2` (the guest entry the next `eret` resumes at); *used* by the entry setup | the guest actually runs from the set entry (round trip) every boot | *refines* — honored |
| `VcpuOps::inject_interrupt` | ✅ | ⏳ **deferred** — no GIC yet; nothing to inject. Not on Arc 4's path; the impl reports rather than silently pretending | when interrupt delivery lands (a later arc) | *assumption named* |
| `GuestMemory::read`/`write` | ✅ | ⏳ **deferred** — the register-based ABI passes args in `x0`/`x1`, so no guest-memory access is needed to service Arc 4's hypercalls | Audit #2 + the negative-isolation test (Arc 5) | *assumption named* |
| global allocator | n/a | ✅ bump over `.bss` (Arc 3, `heap.rs`) | constructs the guest `Hypervisor` every boot | *plumbing* — no reclaim |

### Honest deferred-items note

- **`GuestMemory`** stays deferred to Arc 5, exactly as Audit #1 named it: it is realized as accesses
  through the guest's Stage-2 translation when there is guest memory to read/write. Arc 4's guest
  passes everything in registers, so nothing here relies on it.
- **`VcpuOps::inject_interrupt`** stays deferred: there is no GIC and no interrupt source in Arc 4.
  Realizing it would be a fiction; it is unreachable on Arc 4's path and fails loud if ever reached.
- **The minimal Stage-2 is not the model's `p2m`.** It is a single identity block that runs the
  guest. Faithful `p2m`→descriptor translation, and the negative test that a guest is *faulted* for
  touching unauthorized memory, are **Arc 5 / Architecture Audit #2**. Arc 4 deliberately builds no
  isolation surface — the "don't skip ahead" the roadmap requires.
- **Runtime invariant checks** remain compiled out on the release metal build (`debug_assert!`), as
  Audit #1 named: the metal trusts the ∀-N proof, it does not re-check it at runtime.

## The diamond review pass — verdict SOUND, with one real-hardware gap named

Before proceeding to Arc 5, Arc 4 got a diamond-grade review pass (the same rigor as Arc 3's PR#32):
an own adversarial re-read + ELF disassembly, plus **three independent auditors with distinct lenses**
(Rust-unsafe/soundness; real-silicon fidelity; false-green/test-integrity), converged.

**What held (no defect in any claimed-sound dimension):**
- **Rust soundness — clean.** The GPR trampoline is byte-exact (disasm-verified: `x0..x30` at the
  right offsets, `x30` saved/restored around the `bl`, 16-byte-aligned frame); the Stage-2 index math
  is in-range and identity-correct; the `UnsafeCell`/`Sync` single-CPU-non-nested argument holds; the
  `eret`/`SP_EL2` switch and the re-entry guard are sound. No UB.
- **No false-green.** Every load-bearing witness (the round-trip `70`, the two per-call results, the
  accounting selftest, the `BRK` decode) is genuinely produced by its mechanism and cannot print on a
  failure path. Slot 8 disassembles to a bare `b __guest_sync_entry` (no `w0` clobber). Two cosmetic
  markers hardened with comments (see `boot-test.sh`).
- **QEMU functional correctness — confirmed** three ways; the exception/`eret`/Stage-2 *logic* and all
  constants (`VTCR=0x8002_3559`, block `0x7FD`, `SPSR=0x3C5`, the `dsb/tlbi/isb` order) re-derived
  independently and agree. `hv-core` untouched.

### Real-hardware readiness — the EL2-MMU gap (named, deferred)

The real-silicon auditor found a genuine gap the per-mechanism QEMU-vs-metal lines did not close, and
it is worth stating plainly: ~~**the hypervisor runs the entire time with its own stage-1 MMU off**
(`SCTLR_EL2.M=0`, never enabled), so~~ on real silicon *every EL2 data access is Device-nGnRnE*. That
has two consequences, **both invisible under QEMU/TCG** (which ignores memory type — the reason the
gap was invisible):

> ⚠ **CORRECTED 2026-08-09 — the struck clause is false since #156, and the CONCLUSION SURVIVES IT.**
> Rung A1 turned EL2's stage-1 MMU **on**. But it deliberately reproduced the MMU-off attributes:
> `hv-metal`'s `MAIR_EL2` attr 0 is `Device-nGnRnE` and `SCTLR_EL2.C` is left 0 as a structural
> backstop. So the *memory type* is unchanged and **both consequences below still apply verbatim** —
> which is exactly why this section must say why it survives rather than be quietly deleted. Read
> "the MMU is off" as "EL2's data is Device-nGnRnE", which is the property that actually matters.

1. **Atomics are architecturally UNPREDICTABLE.** `LDXR/STXR` (and LSE atomics) on Device memory are
   CONSTRAINED UNPREDICTABLE; the common outcome is a perpetually-failing `STXR` — a livelock. This
   reaches `IN_GUEST_HANDLER` (Arc 4) and, pre-existing since Arc 3, the bump allocator's
   `compare_exchange`.
   ⚠ **The exposure is larger than those two sites — MEASURED 2026-08-09 on the shipped binary, not
   read off this list.** `hv-metal`'s release build contains **40 exclusive-monitor instructions and
   zero LSE** (`ldaxr`/`stlxr` throughout) — **identical across all nine feature configurations**,
   with 100 in the default debug build — from RMW atomics in **six** modules: `cell.rs`, `heap.rs`,
   `linux.rs`, `pending.rs`, `guest.rs`, `role.rs`. Plain atomic loads and stores are fine; it is the
   read-modify-writes that take the exclusive. **This entry named two sites and was read for years as
   if that were the inventory** — declare how you enumerated, or a list is taken for a census.
   ⚠ **This first shipped saying 244, and the correction is the more useful half.** That figure was
   read off whatever binary happened to be sitting in `target/` — which `boot-test.sh` overwrites
   across seven configurations — and then reported as *the* shipped binary. It reproduces at no
   configuration. The count above was taken by **building each config explicitly and measuring each**,
   which is also what shows the number does not vary. Reading a number off a build directory is
   sampling an artifact whose provenance you did not control (design-lesson #155).
2. **Caches are unmanaged.** Freshly-copied guest code is written (uncached) then fetched (cacheable)
   with no I-cache maintenance; the Stage-2 walker is programmed cacheable while its descriptors are
   written by uncached stores. On silicon either can read stale lines out of the UNKNOWN reset cache
   state. (For Arc 4 *as shipped* the Device write path + the cold first-boot I-cache make it
   incidentally safe; the gap becomes load-bearing on a guest *reload* into a warm-cache window.)

**Scope of this gap (important):** it is *not* introduced by Arc 4 — it spans arcs 0–4 — it does
**not** affect QEMU (our only environment; Apple Silicon gates EL2, so we run under TCG) or the proof,
and it is within the metal's already-declared *real-HW-deferred* scope. It is the honest distance
between "QEMU-sound" and "runs on metal."

**Why it is named-and-deferred rather than fixed now:** the single clean fix is a dedicated
prerequisite arc for the first real-hardware run — **an EL2 stage-1 Normal-cacheable identity map +
`SCTLR_EL2.M/C/I` + boot-time I/D-cache invalidation** (closing atomics *and* caches together). But
its *core payoff* — "atomics stop being UNPREDICTABLE, caches become coherent *on silicon*" — has **no
oracle but real EL2 hardware**: no spec, blind auditor, or QEMU run can confirm it (QEMU shows the same
green boot with or without the fix). Diamonding is oracle-bound; building unvalidatable real-HW code
early carries weight without cutting a diamond. So — per the roadmap decision — **naming this gap
precisely here *is* the diamond for it now**, in the exact spirit of `docs/TIER-D-NONINTERFERENCE.md`
§2.1 (which named the timing channel out of scope rather than proving it). The EL2-MMU arc gets its
full diamond the moment real silicon joins the oracle set. It does not block Arc 5 (fully diamondable
on QEMU — Stage-2 fault semantics are the one thing QEMU is faithful about) since the EL2 stage-1 MMU
is orthogonal to Arc 5's guest Stage-2 work.

> ★★ **THAT "NO ORACLE" CLAIM HAS NOW BEEN TESTED, HALF AND HALF — 2026-08-09.** It was one sentence
> covering two consequences, and the two came apart:
>
> | half | oracle? | evidence |
> |---|---|---|
> | **caches** | ✅ **REFUTED — an oracle exists** | `fvp-probe` m3: Arm's AEM withholds a dirty line from a non-cacheable observer and releases it only on `DC CVAC`. m4 then used it to find a real defect in `scrub_frame` (PR #168) |
> | **atomics** | ❌ **UPHELD — but now MEASURED, not assumed** | `fvp-probe` m5: the AEM executes `LDXR`/`STXR` on `Device-nGnRnE` **normally** — succeeded first attempt, value incremented, against a descriptor printed as `AttrIndx 0` with a Normal-WB control succeeding alongside. It picks a benign CONSTRAINED-UNPREDICTABLE choice, so it cannot grade this hazard either |
>
> **So the deferral stands for atomics, on better grounds than it was made** — "the oracle set is
> QEMU plus silicon" is now a measurement, and the AEM has been struck off it for this hazard
> specifically. ⚠ Read m5 for what it says: *"this model does not exhibit the hazard"* is **not**
> *"the hazard is benign"* — CONSTRAINED UNPREDICTABLE lets implementations differ, so a real core
> may still livelock.
>
> ★ The reusable part: **"no oracle" is a claim about instruments you have looked for, and it decays
> the moment someone builds one.** Half of this sentence was already false when it was quoted in a
> next-move discussion; nobody had checked because it read as settled.

### Other below-bar items named by the review

- **FP/SIMD (`v0..v31`, `FPSR`/`FPCR`) not framed across the resume** — harmless for the register-only
  guest; the FP save/restore lands with the first non-trivial guest (`GuestFrame` doc).
  **CLOSED by ③-b2b-ii-f.** It landed exactly where this predicted — with the first guests that use
  floating point, the two real Linux kernels — though not where the frame is: a trap's frame and a
  switch's context are different things, and only the latter can cross vCPUs. See `hv-metal/src/fp.rs`.
- **`VTCR_EL2.PS` hardcoded to 40-bit** rather than clamped to `ID_AA64MMFR0_EL1.PARange` — fine on
  `virt`; a real-hardware-portability fix reads `PARange`.
- **`SP_EL1` set to the exclusive window end** — a push lands in-window; correct-and-cosmetic.

## Verdict

**A trivial EL1 guest boots behind a minimal Stage-2, issues `HVC`, traps to EL2, and has its
hypercalls decoded through `hv-core`'s ABI seam and serviced by the proven `Hypervisor::dispatch` —
with the result handed back and observed by the guest, witnessed by the guest itself.** `VcpuOps::
set_entry` is realized and honored on ARM; `inject_interrupt` and `GuestMemory` are deferred with
their assumptions named. Three-way converged (spec-derived code + blind Arm-ARM auditor + running
QEMU); one auditor refinement folded in; no soundness defect. Arc 4 *refines* the proof and is
QEMU-sound for the functional round trip — no isolation content, by design. `hv-core` is untouched
and proven; the `unsafe` surface stays fenced in `hv-metal` and justified per block.

The subsequent **diamond review pass** (above) confirmed this verdict — Rust-soundness clean,
no false-green, QEMU-functionally correct — and named one real gap (the EL2-MMU / Device-memory
atomics + cache story) as the prerequisite for the first real-hardware run. Arc 4 is diamond-grade
for QEMU; the real-hardware readiness item is tracked, not silently carried.
