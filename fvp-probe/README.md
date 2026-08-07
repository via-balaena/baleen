<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `fvp-probe` — a local measurement instrument, **not** part of the hypervisor

> ⚠ **This is not shipped code, and it is NOT gated by CI.** It is a standalone bare-metal AArch64
> program for Arm's Base RevC AEM FVP, written to answer one question that QEMU structurally cannot.
> It shares no code with `hv-metal`, depends on no workspace crate, and is excluded from the
> workspace. If it rots, nothing in the product breaks — **that isolation is the whole design.**

## Why it exists

Honest-ledger item **2(d)**: *the STE's VMID field and the stage-2 TLBI are not boot-witnessed.*

That gap is not laziness. **QEMU's SMMU models no translation caching at all**, so there is nothing
for an invalidation to invalidate and nothing a VMID could tag. "The TLBI made no difference" and
"the TLBI is unimplemented" are the same observation there — the experiment is unrunnable, not
merely unrun.

Arm's AEM does model it, and makes it a parameter:

```
pci.pci_smmuv3.mmu.size_of_tlb        = 0   "The number of entries in the TLB."
pci.pci_smmuv3.mmu.size_of_ste_cache  = 0   "...cache holding STE structures."
```

★ **The default of zero is a built-in control.** The same binary run twice must give opposite
answers: caching off ⇒ a stale mapping is impossible; caching on ⇒ a stale mapping is expected. A
witness that can only be run in the configuration where it passes is design-lesson #198's failure
mode; here the negative arm costs one command-line flag.

## Why it is NOT a CI gate, and must not become one

Decided deliberately — the reason is **engineering, not licensing**:

* the FVP **cannot be cached or redistributed**, so a gate would re-fetch it from Arm every run;
* under a licence Arm may **terminate at any time**;
* and it runs at **~4.6 MIPS** (measured), so anything Linux-sized takes tens of minutes.

Every gate in this repo is pinned — the real-Linux gate reproduces a checksum-pinned kernel
byte-for-byte. An unpinnable dependency cannot meet that bar. Its failure mode would be "`main` is
red because Arm changed something."

## Running it

```sh
fvp-probe/host/fetch-fvp.sh        # ~91 MB from Arm + 30 MB Ubuntu Base, all hash-checked
fvp-probe/host/mkinitramfs.sh      # the VM image that carries the model (slow, cached)
fvp-probe/host/run-fvp.sh          # build the probe, run it, print the transcript
fvp-probe/host/run-fvp.sh --cache-on      # the other arm of the control
fvp-probe/host/run-fvp.sh --list-params   # what knobs does this model really have?
```

The model is Linux-only (no macOS build exists), so on this laptop it runs inside a QEMU/HVF VM
booted from the **same checksum-pinned Alpine kernel the real-Linux gate uses**, with an Ubuntu Base
userspace in an initramfs. Artifacts land in `.fvp/` (gitignored — Arm grants no redistribution
right). See `host/` for the reasoning; each script carries its own.

> ⚠ **These scripts exist because the first version of this harness did not.** It was built in a
> session scratchpad on 2026-08-07 and never checked in, so by the next morning the tarball, the
> initramfs and every script were gone and only a prose recipe survived. **Rebuilding cost more than
> writing it had.** Design-lesson #187 in its cheapest form: nothing enforced "keep the scripts", and
> nothing announced the loss.

## Status

**Milestone 1 — done, and re-established from the checked-in harness.** Boot on the FVP at EL3,
initialise PL011, report `CurrentEL`, `MPIDR_EL1`, and `SMMU_IDR0`/`S2P`/`S1P` read from the real
SMMU. Measured:

```
@@ CurrentEL   = 0x3            EL3 at reset
@@ MPIDR_EL1   = 0x81000000     RES1 + MT set  (QEMU virt leaves MT clear)
@@ SMMU_IDR0   = 0x080fe6bf
@@ SMMU_S2P    = 0x1            stage-2 supported   (IDR0 bit 0)
@@ SMMU_S1P    = 0x1            stage-1 supported   (IDR0 bit 1)
```

2 572 instructions, 0.761 GB model highwater, exit status 0.

**Milestone 2 — not written.** Stream table + command/event queues, an STE for an
`SMMUv3TestEngine`, a DMA, then: mutate the STE with **no** invalidation and DMA again (stale ⇒
caching is real), then `CMD_CFGI_STE` / `CMD_TLBI_*` and DMA again (changed ⇒ invalidation matters).
Run the whole thing twice, with `size_of_tlb`/`size_of_ste_cache` at `0` and at `N`.

## Platform facts this depends on (each corroborated twice)

| fact | value | sources |
|---|---|---|
| DRAM base (link address) | `0x8000_0000` | FVP guide; `bp.dram_size=4` |
| PL011 UART0 | `0x1c09_0000` | TF-A `V2M_IOFPGA_UART0_BASE`; model's `bp.uart_base` |
| SMMUv3 | `0x2b40_0000` | TF-A `PLAT_FVP_SMMUV3_BASE`; FVP guide table; **and `IDR0` read back here** |
| GICD / GICR | `0x2f00_0000` / `0x2f10_0000` | TF-A `BASE_GIC*_BASE`; Linux `fvp-base-revc.dts` |
| **PCIe ECAM** | **`0x4000_0000`** (256 MiB, bus 0–0xff) | Linux `fvp-base-revc.dts`; its PCI MEM window `0x5000_0000` matches TF-A `PLAT_ARM_PCI_MEM_1_BASE` |

## The three assumptions this platform has already falsified

Each was carried over from QEMU `virt`, each was invisible until measured, and **each produced
silence rather than an error**. They are the argument for the instrument, not against it.

**1. The UART is disabled at reset.** The first version skipped PL011 initialisation, reasoning that
"the model accepts `DR` writes from reset". True on QEMU `virt`, false here
(`bp.pl011_uart0.uart_enable=0`). Symptom: not one byte.

**2. DRAM is behind a TZC-400, and there is no firmware to open it.** The Base RevC guards DRAM with
a TrustZone Address Space Controller that comes up denying access; on a normal boot TF-A's BL1/BL2
programs it first. A bare-metal image loaded straight into DRAM has no such firmware. The model says
so plainly —

```
Error: This image is attempting to run from DRAM, which is access controlled by the TZC-400.
Try running firmware beforehand or use parameter bp.secure_memory=false
```

— **and then carries on**, reporting `PC=0x8000_0000` and warning only that "simulation performance
will be reduced". So the run looks alive and produces nothing. `bp.secure_memory=false` is therefore
load-bearing in `run-fvp.sh`, and QEMU `virt` has no analogue: there, RAM is RAM.

⚠ **The milestone-1 command line recorded in this file did not include that flag**, and re-running it
as written produces no output at all. **The recorded recipe was not the recipe that ran** — which is
precisely why the recipe is now a script in `host/` rather than a code block in a README.

**3. `IDR0.S2P` is bit 0, and reading bit 1 gave the right answer anyway.** Milestone 1 read
`(idr0 >> 1) & 1` — that is `S1P` — and reported it as `S2P`. It printed `0x1` and was recorded as
"stage-2 supported": true, but not established by that line, because `IDR0 = 0x080fe6bf` has **both**
bits set and the two readings are indistinguishable here.

★ **The same defect, with the same cause, had already been found and fixed once**: SMMU rung 1 had
`IDR0_S1P`/`IDR0_S2P` swapped, it changed no result because QEMU also sets both, and
`hv-metal/src/smmu.rs` carries the correction *and* a note explaining it. It recurred because this
crate deliberately shares no code with `hv-metal`, so **isolation from the hypervisor's code is also
isolation from its corrections.** That is a real, recurring cost of this crate's design. It is still
the right trade — a rotting instrument must not be able to break the product — but it is paid with
attention, not avoided. Both bits are now printed, so the reading is falsifiable on a machine where
they differ.
