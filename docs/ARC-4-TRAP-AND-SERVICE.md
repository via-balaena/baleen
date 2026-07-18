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

## Verdict

**A trivial EL1 guest boots behind a minimal Stage-2, issues `HVC`, traps to EL2, and has its
hypercalls decoded through `hv-core`'s ABI seam and serviced by the proven `Hypervisor::dispatch` —
with the result handed back and observed by the guest, witnessed by the guest itself.** `VcpuOps::
set_entry` is realized and honored on ARM; `inject_interrupt` and `GuestMemory` are deferred with
their assumptions named. Three-way converged (spec-derived code + blind Arm-ARM auditor + running
QEMU); one auditor refinement folded in; no soundness defect. Arc 4 *refines* the proof and is
QEMU-sound for the functional round trip — no isolation content, by design. `hv-core` is untouched
and proven; the `unsafe` surface stays fenced in `hv-metal` and justified per block.
