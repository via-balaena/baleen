<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# M5 Arc 5 — the guest hardware interface: interrupts, timer, PSCI

Arc 5 gives a guest the three things it needs from a hypervisor beyond memory and virtio: **interrupts**,
a **timer**, and **PSCI** (power). This is the plumbing that a real Linux guest will use at the capstone;
it is built and proven here with synthetic guests that drive the **real** hardware interfaces, so a Linux
kernel uses them unchanged. **No new isolation content** — the isolation thesis is already proven on the
Arc 0–4 synthetic guests; Arc 5 adds capabilities, audited only for whether they open a new cross-domain
channel (Audit #7: they do not). `hv-core`/`hv-hal` are untouched (this refines).

## The approach — hardware GIC virtualization, not software emulation

The QEMU `virt` machine (with `gic-version=3`) exposes the ARM **GIC virtualization extensions** at EL2 —
the `ICH_*` list registers. Rather than emulate a GICv3 in software, the hypervisor makes a virtual
interrupt *pending* for the guest by writing a list register (`ICH_LR0_EL2`) and lets the hardware CPU
interface deliver it — exactly how KVM and Xen do it. `hv-metal/src/gic.rs` holds the vGIC.

## The sub-arcs (each boot-tested, CI-green)

- **5a — vGIC injection.** Enable the virtual CPU interface at EL2 (`ICC_SRE_EL2`, `ICH_HCR_EL2.En`,
  `HCR_EL2.IMO`); a synthetic guest enables its GICv3 CPU interface (`ICC_SRE_EL1`/`PMR`/`IGRPEN1`) and
  acknowledges an injected virtual interrupt via `ICC_IAR1_EL1`. (Surfaced + fixed: the machine defaulted
  to GICv2 — no GICv3 CPU-interface system registers — so `gic-version=3` was added to the machine args.)
- **5b — async vectored delivery + the virtual timer.** (1) A guest installs its **own EL1 vector table**
  (`VBAR_EL1`, via a 0x800-aligned blob so the table lands aligned), unmasks IRQs (`DAIFClr`), and *takes*
  the injected interrupt at its IRQ vector — real vectored delivery. (2) A guest uses the architected
  **virtual timer** (`CNTV`) for timekeeping: program `CNTV_TVAL`, poll `CNTV_CTL.ISTATUS` to expiry.
- **5c — PSCI.** The HVC handler recognizes PSCI function IDs (SMC convention) and services `PSCI_VERSION`
  (v1.1), `PSCI_FEATURES`, and `SYSTEM_OFF` (the guest powers off). A guest queries the version and powers
  off — exactly how Linux uses PSCI with `method = "hvc"`.
- **5d — the timer TICK (the EL2-IRQ keystone).** The full physical-interrupt delivery path. A guest
  programs its virtual timer with the interrupt un-masked; the timer fires the physical PPI 27, routed to
  EL2 by `HCR_EL2.IMO`; a **new EL2 IRQ handler** (vector slot 9 → `__guest_irq_entry` → `handle_guest_irq`)
  acknowledges the physical interrupt, disables the level-triggered timer so it does not re-fire, and
  injects the matching **virtual** interrupt; the guest takes it asynchronously at its EL1 vector. This
  required real physical GICv3 init (distributor + this CPU's redistributor wake + enable PPI 27) and the
  EL2 physical CPU interface. This receive→inject path is what virtio used-buffer interrupts reuse.

## What remains — the real Linux capstone (5e), kernel-gated

With the interface proven, the capstone is booting a real Linux guest: a large guest-RAM Stage-2 map,
device pass-through (PL011 + GICv3 for a single guest that owns the machine, with `IMO=0` — the vGIC
injection path above is the *multi-guest* mechanism), a DTB (dtc / the QEMU-generated blob), a minimal
kernel `Image` + initramfs loaded per the arm64 boot protocol (`x0` = DTB), and virtio interrupts pended
into the real distributor. The one input this environment cannot itself produce is the **kernel `Image`**
(no aarch64 Linux cross-toolchain here); it is a documented drop-in seam for a focused follow-up.

## Scope and honesty

- **Plumbing, no isolation content.** Arc 5 adds capabilities; the thesis (Arc 0–4) is untouched.
- **Single-guest-per-phase.** Each phase runs one interrupt-capable guest; the vGIC list-register state
  is per-CPU EL2 context. Scheduling *multiple* interrupt-capable guests concurrently would make the
  `ICH_*` state part of the per-vCPU context to save/restore on a switch (like `GuestContext` for GPRs) —
  a named forward obligation, not needed for Arc 5's model. See Audit #7.
- `hv-core`/`hv-hal` untouched. Every `unsafe` is EL2-legal GIC/timer register or GIC MMIO access.
