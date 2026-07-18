<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Architecture Audit #1 — the `hv-hal` fence

*The centerpiece of M3 Arc 3, and the first point where the ∀-N model proofs make contact with real
hardware. The proofs cover the `hv-core` **model**; they hold on the metal only insofar as the metal
honors the southbound trait surface (`hv-hal`) exactly as the model assumes. This audit enumerates
that surface, asks of each element "is it architecture-neutral, and does the ARM metal honor it — or
must we name an assumption?", and records the verdict. A clean audit is a valid result and the
confidence artifact (design-lesson #17); a named assumption is an honest debt carried forward, not a
gap swept under the rug.*

## The charter — what `hv-core` trusts the HAL to guarantee

`hv-core` is `no_std`, zero-`unsafe`, and reaches the outside world **only** through `hv-hal`
(`hv-hal/src/lib.rs`). It never touches a register, a page table, or a device. So the *entire*
attack surface between the proven model and the metal is these three traits and two type aliases.
Two properties must both hold for the proofs to mean anything on hardware:

1. **Neutrality.** The surface names no CPU architecture. If a signature carried a VMCS field, an
   `ept_*` type, or a GIC redistributor, the "same brain on ARM and x86" promise would be a fiction
   and the proofs would be entangled with one ISA. This is the standing constraint from
   [[baleen-arm-target]] — ARM-first, x86 co-equal.
2. **Fidelity.** Each trait the ARM metal *implements* must behave as the model assumes — a
   `TimeSource` that runs backwards, or a `GuestMemory::read` that returns the wrong bytes, would
   silently falsify the proof at the seam. Where a trait is **not yet** implemented on ARM, the
   assumption is named and deferred to the arc that realizes it.

## The surface, enumerated

The whole fence, as of Arc 3 (`hv-hal/src/lib.rs`):

| element | kind | Arc-3 status |
|---|---|---|
| `Gpa = u64` | type alias | guest-physical address; a plain integer |
| `Ticks = u64` | type alias | opaque monotonic time; a plain integer |
| `MemError` | enum | `{ OutOfBounds }` |
| `GuestMemory::read(&self, Gpa, &mut [u8]) -> Result<(), MemError>` | trait method | **deferred** (M4/Arc 5) |
| `GuestMemory::write(&mut self, Gpa, &[u8]) -> Result<(), MemError>` | trait method | **deferred** (M4/Arc 5) |
| `TimeSource::now(&self) -> Ticks` | trait method | **realized** on ARM this arc |
| `VcpuOps::inject_interrupt(&mut self, u8)` | trait method | **deferred** (M4) |
| `VcpuOps::set_entry(&mut self, u64)` | trait method | **deferred** (M4) |

### Neutrality verdict — per element

- **`Gpa`, `Ticks`** — plain `u64`. No architecture. A guest-physical address and a monotonic tick
  are ISA-independent concepts; the *width* is 64-bit on both targets. ✅ neutral.
- **`MemError::OutOfBounds`** — an access outside the guest's physical address space. Neither ARM
  nor x86 appears. ✅ neutral.
- **`GuestMemory`** — addresses are `Gpa` (integer), payloads are `&[u8]` (bytes). No page-table
  format, no descriptor bits, no Stage-2 / EPT concept leaks into the signature. The *implementation*
  will walk AArch64 Stage-2 (or x86 EPT), but the trait says only "read/write these bytes at this
  guest-physical address, or fail out-of-bounds." ✅ neutral.
- **`TimeSource`** — returns `Ticks`. No timer register named. The ARM impl reads `CNTPCT_EL0`, an
  x86 impl would read the TSC; the trait knows neither. ✅ neutral, and **realized** — see below.
- **`VcpuOps`** — `inject_interrupt(vector: u8)` takes an 8-bit interrupt vector (neutral: both a GIC
  INTID and an x86 vector fit a `u8`); `set_entry(entry: u64)` takes a guest program counter. The
  *types* are neutral. **One naming leak was found and fixed** — see finding F2.

**Overall neutrality verdict: ✅ the fence is architecture-neutral.** No signature carries a VMCS
field, an `ept_*`/Stage-2 descriptor type, a GIC/LAPIC concept, or a VMSA register. x86 plugs in
behind exactly these traits. The two leaks found were both *cosmetic* (a doc claim and a parameter
name), below the soundness bar, and are fixed in this same change.

## Findings (both fixed in this PR)

- **F1 — stale doc claim (documentation).** The `hv-hal` module doc asserted *"the first `hv-metal`
  backend is x86-64 (Intel VMX / EPT, the LAPIC)."* That contradicts the ARM-first reality: the
  first backend **is** AArch64/EL2, standing up under QEMU right now. Left unfixed it would mislead a
  reader about which ISA the fence was first exercised against. **Fixed:** the doc now names AArch64
  as the first backend with x86 co-equal, and points at this audit. (No code change.)
- **F2 — `rip` parameter name (neutrality leak).** `VcpuOps::set_entry(&mut self, rip: u64)` used
  `rip` — the x86-64 instruction-pointer register — as the parameter name in a trait that is supposed
  to be ISA-agnostic. The *type* was already neutral (`u64`); only the *name* leaked x86 origin. On
  AArch64 the guest entry lands in `ELR_EL2` / the guest `PC`. **Fixed:** renamed to `entry` in the
  trait and the `hv-sim` impl, with a doc note that the trait names neither `RIP` nor `ELR`. Trait
  parameter names do not bind implementers, so nothing downstream broke; `cargo test --workspace`
  stays green.

Neither finding is a soundness issue. That the audit's only findings are a doc line and an
identifier is itself the result: the fence was built neutral and stayed neutral through three arcs.

## Fidelity — realized vs. named-assumption, per trait

### `TimeSource` — **REALIZED on ARM this arc** ✅

`hv-metal/src/time.rs` implements `TimeSource::now` over the generic timer's physical count
(`CNTPCT_EL0`). The contract is exactly "does not run backwards"; the ARM realization honors it:

- **Monotonic / never-backwards** — the ARMv8-A system counter increments at a constant rate, is
  ≥56-bit, and does not run backwards outside counter power-down (which does not occur under EL2
  execution or QEMU). The boot **witnesses** this (`witness_advance`): it observes the count
  non-decreasing across a bounded spin *and* strictly advancing (live, not frozen at zero), and the
  CI boot-test matches the marker. So the fidelity claim is not merely asserted from the spec — it is
  checked on every boot.
- **Readable at EL2** — the physical count needs no enable bit at EL2 (`CNTHCTL_EL2` gates only
  EL0/EL1). Confirmed independently by the blind auditor.
- **Ordering** — `now()` issues an `isb` before the read so the count cannot be speculated out of
  program order on real silicon. This is a deliberate **per-mechanism QEMU-vs-metal** line
  (design-lesson #23): QEMU's TCG would never expose the reorder, so the barrier is invisible under
  emulation and load-bearing on metal (`docs/QEMU-AND-METAL.md` item 2).
- **`CNTFRQ_EL0` caveat** — the *frequency* is a firmware/QEMU-programmed label, not measured
  hardware; it is print-only and does **not** back the `Ticks` (which are the raw count). So the
  advisory nature of `CNTFRQ_EL0` cannot corrupt the monotonicity the model depends on. (Observed
  under `-cpu max`: 1 GHz — QEMU's choice; the code depends on none of it.)

### `GuestMemory` — **named assumption, deferred to M4/Arc 5** ⏳

No guest memory exists until the first EL1 guest and its Stage-2 tables (M4). **Assumption named:**
the ARM impl will realize `read`/`write` as accesses through the guest's Stage-2 translation such
that they move exactly the bytes at the given `Gpa` and return `OutOfBounds` for any address outside
the guest's physical space — no more, no less. This is precisely the refinement **Architecture Audit
#2** (M4/Arc 5) is chartered to verify (the model→page-table bridge + the negative-isolation test).
Recorded here so the debt is explicit, not discovered later.

### `VcpuOps` — **named assumption, deferred to M4** ⏳

No vCPU is run until M4's trap-and-service loop. **Assumption named:** `inject_interrupt` will queue
`vector` for delivery on the next guest entry (via the GIC), and `set_entry` will set the guest PC
for the next `ERET` (via `ELR_EL2`). Nothing in Arc 3 relies on either; they are defined now only to
fix the shape of the fence before hardware exists behind them.

### Two cross-cutting assumptions Arc 3 introduces

- **A global allocator exists and succeeds.** `hv-core` uses `alloc` (the event-channel port table;
  the per-domain `Vec`s). Arc 3 supplies one — a bump allocator over a 256 KiB `.bss` arena
  (`hv-metal/src/heap.rs`). **Assumption named:** allocation succeeds for the sizes the hypervisor
  needs. The bump allocator never reclaims (`dealloc` is a no-op) and can only fail by exhausting the
  arena → null → the default alloc-error handler aborts. For the construct-once, dispatch, and park
  bring-up this never triggers; a reclaiming allocator tied to the long-running control domain is
  M5's concern. No isolation content.
- **The model's runtime invariant checks do not run on metal.** `Hypervisor::dispatch` re-checks the
  cross-subsystem invariants under a `debug_assert!`, compiled out in the `--release` metal build.
  This is *intended*: those invariants are **proven** ∀-N (Tiers A–D), not relied upon at runtime —
  the metal trusts the proof, exactly as designed. Named so the reader does not mistake a green metal
  boot for a runtime-checked one; the guarantee is the proof, and the boot is functional evidence the
  proven logic executes and returns correct values.

## Method — three-way convergence

Per the arc-0–2 discipline (design-lesson #24), the register-level claims this arc makes were
established three independent ways, and they agree:

1. **Spec-derived code** — the `HCR_EL2` fields and the generic-timer registers were read from the
   Arm ARM (register descriptions, section D1) and encoded in `el2.rs` / `time.rs`.
2. **A spec-blind auditor** — an independent re-derivation from the Arm ARM, with no sight of the
   code, confirmed: `HCR_EL2.RW` = bit 31; reset is architecturally UNKNOWN (so *write* the full
   value — which also pins `E2H`=0, without which `RW` loses its non-VHE meaning); the guest-trap
   bits (`VM`, `TGE`, `IMO`/`FMO`/`AMO`, the trap group) are safe left 0 pre-guest; `CNTPCT_EL0` is
   the right EL2 clock, readable at EL2 with no enable, monotonic; `CNTFRQ_EL0` is a firmware label;
   and an `isb` should precede the count read against speculative reordering. Every claim converged
   with the code; two refinements it surfaced (full-write over RMW; the `isb`) were folded in.
3. **The running emulator** — QEMU booted the image and printed `HCR_EL2 = 0x0000000080000000`
   (exactly bit 31, all else 0), a live monotonic count, and the dispatched `HvCall` returning
   `balance=100`. QEMU is architecturally faithful about system registers, the exception model, and
   functional dispatch, so it is a valid third oracle for these mechanisms (`docs/QEMU-AND-METAL.md`).

## Verdict

**The `hv-hal` fence is architecture-neutral, and the one trait Arc 3 realizes on ARM
(`TimeSource`) honors its contract — witnessed on every boot.** The remaining traits
(`GuestMemory`, `VcpuOps`) are unimplemented on ARM by design; their assumptions are named above and
carried to the arcs that realize them (Audit #2 for `GuestMemory`). Two cosmetic neutrality leaks
were found and fixed. No soundness defect. Arc 3 *refines* the proof (the HAL realizes the model's
southbound assumptions) and is QEMU-sound for the functional dispatch — the honest scope, per the
ledger in `docs/ROADMAP.md`.

## The M3 HAL ledger

| trait / type | neutral? | ARM metal (Arc 3) | fidelity check | verified scope |
|---|---|---|---|---|
| `Gpa`, `Ticks`, `MemError` | ✅ | — (plain types) | — | neutral by inspection |
| `GuestMemory` | ✅ | ⏳ deferred (M4/Arc 5 Stage-2) | Audit #2 + negative-isolation test | *assumption named* |
| `TimeSource` | ✅ | ✅ realized (`CNTPCT_EL0`, `isb`-ordered) | `witness_advance` on every boot | *refines* — honored |
| `VcpuOps` | ✅ (after F2 fix) | ⏳ deferred (M4 run loop) | when the run loop lands | *assumption named* |
| global allocator | n/a | ✅ bump over `.bss` (`heap.rs`) | constructs `Hypervisor` + dispatches on every boot | *plumbing* — no reclaim |
