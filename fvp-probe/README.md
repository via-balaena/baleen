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

## Status

**Milestone 1 — done.** Boot on the FVP at EL3, initialise PL011, report `CurrentEL`, `MPIDR_EL1`,
and `SMMU_IDR0`/`S2P` read from the real SMMU. Measured:

```
@@ CurrentEL   = 0x3            EL3 at reset
@@ MPIDR_EL1   = 0x81000000     RES1 + MT set  (QEMU virt leaves MT clear)
@@ SMMU_IDR0   = 0x080fe6bf
@@ SMMU_S2P    = 0x1            stage-2 supported
```

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
| GICD / GICR | `0x2f00_0000` / `0x2f10_0000` | TF-A `BASE_GIC*_BASE` |

⚠ **The UART needs explicit initialisation on this platform.** The first version of this program
skipped it — true on QEMU `virt`, false here (`bp.pl011_uart0.uart_enable=0`) — and produced total
silence. That is the exact class of error the platform-fact diff was done to prevent, and it still
landed in the first forty lines written afterwards.

## Building and running

```sh
cd fvp-probe && cargo build --release      # -> target/aarch64-unknown-none-softfloat/release/fvp-probe
```

The FVP is Linux-x86_64/AArch64 only, so on macOS it runs inside a small QEMU/HVF VM. The recipe —
reuse `.baleen-linux/Image`, an Ubuntu Base rootfs and the FVP package in a single **initramfs** (no
virtio-blk, no 9p, no network, because that kernel ships no modules) — plus the one missing
transitive dependency (`libatomic.so.1`, an 11.6 KB `.deb`) is recorded in the `baleen-hardware`
memory note. Then:

```sh
FVP_Base_RevC-2xAEMvA -a fvp-probe.elf \
  -C bp.vis.disable_visualisation=1 -C bp.terminal_0.start_telnet=0 \
  -C cluster0.NUM_CORES=1 -C cluster1.NUM_CORES=1 \
  -C bp.pl011_uart0.uart_enable=1 \
  -C bp.pl011_uart0.out_file=uart0.log -C bp.pl011_uart0.unbuffered_output=1 \
  --cyclelimit 200000000
```
