<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Architecture Audit #7 — does the interrupt/timer/PSCI surface open a cross-domain channel?

Arc 5 is plumbing: it adds interrupts (vGIC), a timer, and PSCI. It carries **no new isolation property**
to prove — the thesis is already established on the Arc 0–4 synthetic guests. So Audit #7 asks the one
question a capability arc must answer: **does any of the new surface open a channel by which one domain
could observe or affect another?** The audited code is `hv-metal/src/gic.rs`, the EL2 IRQ path in
`hv-metal/src/guest.rs` (`__guest_irq_entry`/`handle_guest_irq`), and the PSCI handler. `hv-core`/`hv-hal`
are untouched.

## The charter

> Every interrupt, timer read, and PSCI call must be confined to the domain that caused it. No injected
> interrupt, timer value, or power action may cross to another domain, and no new shared mutable state may
> become a covert channel between domains.

## The surfaces, one by one

- **vGIC injection (`ICH_LR0_EL2`).** The hypervisor injects a virtual interrupt into the **currently
  running** guest's virtual CPU interface. The list registers are per-PE EL2 state; each phase runs one
  guest, and injection only ever names an interrupt for that guest. There is no register or path by which
  domain A's injection reaches domain B. ✅
- **Physical GIC receive (the timer PPI).** EL2 receives the physical virtual-timer PPI and injects the
  virtual interrupt into the running guest only. The physical distributor/redistributor is initialized by
  the hypervisor (not a guest), and the guest never touches it in this arc. ✅
- **The virtual timer (`CNTV`, `CNTVOFF_EL2`).** Per-guest: `CNTVOFF_EL2` is zeroed per phase, and the
  guest's `CNTV_*` are its own. A timer read yields the guest's own virtual count. No cross-domain read. ✅
- **PSCI.** The handler services the calling guest: `PSCI_VERSION`/`PSCI_FEATURES` are pure reads;
  `SYSTEM_OFF` ends the caller's own phase. No PSCI call names or affects another domain (in particular no
  `CPU_ON` targeting a peer — SMP secondary bring-up is out of scope, single-CPU). ✅

## The one forward obligation (named, not a defect)

Arc 5 runs **one interrupt-capable guest per phase**. The vGIC list-register / `ICH_*` state is per-PE
context that currently belongs to the single running guest. If a future arc scheduled **multiple**
interrupt-capable guests concurrently on one PE (as Arc 1/2 time-slice cooperative guests), that vGIC
state would become part of the per-vCPU context that MUST be saved and restored on a context switch —
exactly as `GuestContext` already saves the GPRs/system registers — or one guest could see another's
pending interrupts. This is a standing obligation for the concurrent-interrupt case, recorded here so it
is not forgotten; it is **not reachable** in Arc 5's single-guest-per-phase model, where no switch occurs
while an interrupt is pending.

## Verdict

**SOUND — no cross-domain channel.** Every interrupt, timer read, and PSCI action in Arc 5 is confined to
the domain that caused it; the shared physical GIC is hypervisor-owned and never a guest-to-guest path.
The concurrent-interrupt save/restore obligation is named for the future and does not arise here.

## Review pass — the new unsafe / GICv3 / asm surface

Because Arc 5 added substantial new `unsafe` (GICv3 system registers, physical-GIC MMIO, the EL2 IRQ
trampoline), a spec-blind auditor reviewed that surface against the GIC spec / QEMU `virt` map.
**Verdict: SOUND, no defect.** Confirmed: the `ICH_LR0_EL2` field encodings; the physical GIC bases and
register offsets + the redistributor wake handshake; INTID 27 as the EL1 virtual-timer interrupt; the EL2
IRQ trampoline's byte-identical guest resume (and that `handle_guest_irq` never mutates the frame/ELR/SPSR
— correct for an async IRQ); **re-entrancy safety** (an exception to EL2 sets `PSTATE.I`, and only `IMO`
not `FMO` is set, so the hypervisor never runs with EL2 IRQs unmasked — no nesting); the **timer-storm
prevention** (`disable_vtimer` deasserts the level-triggered PPI before `eoi_physical`); the PSCI FID
classification (no overlap with the tiny internal `nr`s); and the guest asm (vector-table alignment,
`DAIFClr`, `CNTV` programming, `IAR1`/`EOIR1` sequences).

Two below-bar observations folded into the review-pass commit:
- **Self-contained EL2 CPU-interface enable** — `enable_physical_cpu_interface_el2` now sets
  `ICC_SRE_EL2.SRE` itself rather than relying on an earlier phase having set it (a latent ordering trap
  if the timer path were reused standalone, e.g. at the capstone).
- **RWP note** — `init_physical_vtimer` documents that a real-silicon port should poll `GICD_CTLR.RWP`
  after changing ARE (QEMU completes synchronously, so it is sound to omit here).
