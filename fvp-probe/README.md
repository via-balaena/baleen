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

⚠⚠ **"ZERO ENTRIES" DOES NOT MEAN "NO CACHE", AND THAT MISREADING WAS THIS PROBE'S FOUNDING
PREMISE.** The model says so itself — every `size_of_*` parameter's description ends:

> "If this is zero then it is treated as a large number ('infinite') but it is bounded"

So the default is an **infinite** cache, and the arm first labelled "caching ON" (64 entries) made it
*smaller* than the default. Both arms cached, which is why the first comparison produced identical
columns — the outcome that sent me to read the descriptions.

★ **The design principle survived its premise being false, and that is the only reason the error was
caught.** A witness runnable only in the configuration where it passes is design-lesson #198's
failure mode, so `--both` was built to make reporting one arm harder than reporting the pair. The
comparison then falsified its own control before any result was written up. Had only the default arm
been run, three clean-looking findings would have shipped behind a control that did not exist.

The arms now compare cache **capacity** — infinite versus one entry — because no setting appears to
disable the cache at all.

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

**Milestone 2a — in progress: PCIe enumeration done.** Bus 0 is walked and every function reported
with its BAR sizes (below). This had to come first: milestone 2 needs a bus master it can actually
drive, and whether one existed was in dispute between two sources.

**Milestone 2 — done. Honest-ledger item 2(d) is closed, both halves.**

The instrument is **ATOS** (`SMMU_GATOS_*`), not a DMA device — Arm publishes no register map for the
`SMMUv3TestEngine` and the model exposes none, so the translation itself is the observable instead of
where some bytes landed. IHI 0070D.a §9: an ATOS translation *"interacts with configuration and TLB
invalidation in the same way as a translation that is performed for a transaction"*.

| experiment | infinite cache (default) | minimal cache (`size_of_tlb=1`) |
|---|---|---|
| **2b** STE cache / `CMD_CFGI_STE` | STALE | STALE |
| **2c** stage-2 TLB / `CMD_TLBI_*` | STALE | STALE |
| **2d** `S2VMID` tagging | **SCOPED** | **UNSCOPED** |

**2c — the stage-2 TLBI is load-bearing.** Change one block descriptor, ask again without
invalidating: the old frame comes back. Issue `CMD_TLBI_*`: the new one does.

```
2c.1 baseline           PA=0x82000000     A
2c.2 desc→B, NO TLBI    PA=0x82000000     A   ← stale
2c.3 after TLBI         PA=0x82400000     B   ← invalidation matters
```

**2d — cached entries are `S2VMID`-tagged.** Two StreamIDs, *the same tables*, different VMIDs.
Invalidate one VMID and exactly one stream goes fresh:

```
2d.2 f0/vmid=11 and f1/vmid=22, desc→B, no TLBI   both A     both stale
2d.3 after TLBI(vmid=11)   f0 → B (fresh)   f1 → A (still stale)   ← the tag
2d.4 after TLBI(vmid=22)   f1 → B                                  ← control
```

★ **And it is capacity-dependent, which is what makes it evidence.** With a one-entry TLB the two
streams evict each other, no staleness survives to be scoped, and the result flips to `UNSCOPED`.
A difference that disappears when the cache is made too small to hold it is caused by the cache.

**2b — the STE configuration cache is real too**, which the ledger did not ask about: rewriting the
STE without `CMD_CFGI_STE` leaves the old binding in force, and issuing it installs the new one.

### ⚠ What this does NOT establish

* **It is ATOS, not a bus master.** The architecture says ATOS shares the caches a transaction uses,
  and that sentence is doing real work in the claim. No device DMA was performed.
* **It is a MODEL, not silicon** — Arm's architecture-conformance model, which is stronger evidence
  than QEMU and weaker than hardware.
* **No configuration disables the SMMU cache**, so there is no true negative arm; what stands in for
  it is each experiment's own post-invalidation step plus 2d's capacity control.

## Platform facts this depends on (each corroborated twice)

| fact | value | sources |
|---|---|---|
| DRAM base (link address) | `0x8000_0000` | FVP guide; `bp.dram_size=4` |
| PL011 UART0 | `0x1c09_0000` | TF-A `V2M_IOFPGA_UART0_BASE`; model's `bp.uart_base` |
| SMMUv3 | `0x2b40_0000` | TF-A `PLAT_FVP_SMMUV3_BASE`; FVP guide table; **and `IDR0` read back here** |
| GICD / GICR | `0x2f00_0000` / `0x2f10_0000` | TF-A `BASE_GIC*_BASE`; Linux `fvp-base-revc.dts` |
| **PCIe ECAM** | **`0x4000_0000`** (256 MiB, bus 0–0xff) | Linux `fvp-base-revc.dts`; its PCI MEM window `0x5000_0000` matches TF-A `PLAT_ARM_PCI_MEM_1_BASE`; **and enumerated here** |
| **`SMMU_IDR1`** | **`0x0e739d20`, `SIDSIZE = 32`** | read from the device (QEMU `virt` reports `0x02730010`, `SIDSIZE = 16`) |
| **bus masters present** | **two `SMMUv3TestEngine`s at `00:1e.0` and `00:1e.1`** | enumerated here; vendor `0x13b5` device `0xff80`, matching FVP guide §12.5 |

### What bus 0 actually holds — enumerated, not assumed

```
00:00.0  vendor=0x13b5 device=0x00ba class=0x060001   host bridge
00:01.0 … 00:04.0                    class=0x060400   four root ports
00:1e.0  vendor=0x13b5 device=0xff80 class=0xff0000   SMMUv3TestEngine
         BAR0(64) 256 KiB   BAR2(64) 32 KiB   BAR4(64) 4 KiB
00:1e.1  vendor=0x13b5 device=0xff80 class=0xff0000   SMMUv3TestEngine  (same BARs)
00:1f.0  vendor=0x0abc device=0xaced class=0x010601   AHCI
```

★ **Two engines on two functions is `㉑`'s "two bus masters" story natively** — two distinct
RequesterIDs (`0x00f0`, `0x00f1`) with no device-stacking trick, where QEMU needed two `-device edu`s.
Every BAR reads back base `0x0`, so addresses must be assigned by hand.

⚠ **`SIDSIZE = 32` against QEMU's 16**: a linear stream table covering StreamID `0xf0`/`0xf1` still
only needs 256 entries, but nothing here may assume the QEMU value.

⚠ **This table corrects a reading taken from `--list-params`.** That listing reports
`pci.pcie_rc.smmuv3testengine0.endpoint.bar0_log2_size=0`, whose own description says *"zero is
reserved means bar is not used"* — from which I concluded the engines had no register window and
could not be driven. **Wrong**: those parameter names are available *slots*, not the two devices the
platform instantiates, and the live ones carry exactly the BARs §12.5 documents. Reading a parameter
namespace and inferring a hardware fact is the same move that produced the `arm-smmuv3.stage` error
(design-lesson #196). One enumeration run settled what two documents could not.

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


## Milestone 3 — **does this model hold a dirty cache line?** (2026-08-08)

`hv-metal` runs EL2 with `SCTLR_EL2.C = 0` — all data accesses non-cacheable — as a deliberate
backstop (rung A1). Turning caches on is rung **A2**, and it was deferred for one recorded reason:
`scrub_frame`'s confidentiality argument and `smmu::publish`'s ordering obligation must be
*re-derived*, and the re-derivation is **unwitnessable on QEMU**, which models no cache. A wrong
version and a right one look identical there.

The roadmap named the way out — *"whether the AEM models CPU data caches is UNKNOWN and cheap to ask
now that `fvp-probe`'s harness exists"*. Asked, and then **measured**, because the model's own
parameter list saying `cache_state_modelled=1` is a description and not a demonstration:

```text
@@ M3 dcache line = 64 bytes
@@ M3 seed        = 0x5eed5eed5eed5eed   written through the NON-cacheable alias
@@ M3 nc-read     = 0x5eed5eed5eed5eed   ← STALE after a cacheable store of 0xd117…
@@ M3 post-dsb    = 0x5eed5eed5eed5eed   ← STILL stale: a barrier is not a maintenance op
@@ M3 post-clean  = 0xd117d117d117d117   ← DC CVAC released it
@@ M3-VERDICT CACHES-MODELLED
```

One physical page, two mappings (write-back cacheable and non-cacheable), four phases with **both**
controls:

* the **positive** control (`DC CVAC` makes the value appear) is what proves the two aliases are the
  same physical page — without it, a stale read could just mean the probe mismapped something;
* the **negative** control (a bare `dsb sy` changes nothing) is what proves the maintenance
  *operation* is doing the work rather than the barrier that accompanies it.

⚠ **What this establishes is narrow and worth stating exactly.** The AEM withholds a dirty line from
a non-coherent observer until it is cleaned — so a `scrub_frame` that omits its cache maintenance is
**distinguishable here from one that does not**. That is the property A2 needs and QEMU cannot
supply. It is *not* a claim that A2 is correct, or that this model matches any particular silicon.
