<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `hv-metal` — the bare-metal layer (AArch64 / EL2)

**The one crate that carries `unsafe`.** Every other crate in this repo is
`#![forbid(unsafe_code)]`; the metal is where MMIO, system registers, page tables and exception
vectors live, so the `unsafe` is concentrated here deliberately — the fence between this crate and
the proven brain above it *is* the `unsafe` boundary.

## What runs today

Two **unmodified Alpine Linux kernels** boot at EL1 under this hypervisor, with **two vCPUs each**,
time-slicing one physical CPU. They own **no real device MMIO at all**, hold half the RAM window
each, and are refused one another's memory *by the hardware*. An SMMU denies bus-master DMA by
default in the same machine. All of it is under required CI gates.

⚠ **QEMU only.** No board has ever run this — see *The honesty note* below, and read
[`docs/QEMU-AND-METAL.md`](../docs/QEMU-AND-METAL.md) before reading isolation into any QEMU result.

⛔ **This section states what is TRUE, not what arc is current.** The previous version of this file
carried a `## Status: M4, Arc 4` heading and described a trivial `.rodata` guest and a 2 MiB identity
Stage-2 — frozen while the crate grew to 28 modules and real Linux. A "current status" heading is a
claim that rots the moment it stops being tended (design-lesson #276); the arc-by-arc record lives in
[`docs/MILESTONES.md`](../docs/MILESTONES.md), which is append-only and says so.

## Where it sits

It is a **standalone crate** with its own `[workspace]`, **excluded** from the parent workspace: it
targets `aarch64-unknown-none-softfloat` and cannot link for the host, so `cargo test --workspace`
never touches it.

⚠ **That exclusion costs it every `--workspace` gate, not just the one it was excluded for** — its
rustdoc was built by nothing at all until that was noticed. It is now gated out-of-band by
`cargo xtask metal-lint` (fmt, clippy and **rustdoc**, across every feature configuration) and booted
by `cargo xtask qemu-test` / `qemu-linux-test`.

It depends on [`hv-core`](../hv-core/README.md) (the model it dispatches into),
[`hv-hal`](../hv-hal/README.md) (the fence it implements), [`hv-s2`](../hv-s2/README.md) (Stage-2
emission), [`hv-part`](../hv-part/README.md) (the partition arithmetic) and
[`hv-vdev`](../hv-vdev/README.md) (the device models it deploys). **Every one of those is proven; this
crate is the layer that is not** — which is the whole architecture in one sentence.

## Build & run

```sh
rustup target add aarch64-unknown-none-softfloat   # once

cargo xtask qemu             # build + boot interactively (Ctrl-A X to quit)
cargo xtask qemu-test        # headless boot, asserts every boot marker — a REQUIRED CI check
cargo xtask metal-lint       # fmt + clippy + rustdoc, across all feature configurations
```

For the real-Linux path, fetch the checksum-pinned guest image first (~30 s, once):

```sh
hv-metal/linux/fetch-guest-image.sh
cargo xtask qemu-linux        # interactive: two Alpine kernels
cargo xtask qemu-linux-test   # the REQUIRED gate — four boot configurations
```

⚠ **`$BALEEN_LINUX_DIR` can be STALE rather than merely missing**, which makes a healthy tree fail
locally. `fetch-guest-image.sh --force` before believing any local real-Linux failure.
🔧 `BALEEN_KEEP_LOG=1` keeps the serial log even on a green boot.

## Layout

⚠ **Gated** (`cargo xtask doc-modules`): every `src/*.rs` appears here exactly once. A layout table
that silently covers a quarter of the crate is worse than none — the previous version listed **7 of
28** modules and read as complete.

### Boot, diagnostics, and the fence's own realizations

| module | what |
|---|---|
| [`src/main.rs`](src/main.rs) | `_start` (boot-CPU gate, stack, `.bss` zero), `rust_main`, the panic handler |
| [`src/pl011.rs`](src/pl011.rs) | the PL011 UART driver — the metal's diagnostic console |
| [`src/exceptions.rs`](src/exceptions.rs) | `VBAR_EL2` and the 16-entry vector table; the `ESR`-decoding diagnostic handler |
| [`src/abort.rs`](src/abort.rs) | `EC=0x24` data-abort syndrome decode — **one** derivation, two trap handlers |
| [`src/heap.rs`](src/heap.rs) | a bump allocator over a `.bss` arena, so the proven brain can allocate |
| [`src/time.rs`](src/time.rs) | the ARM generic timer behind the `hv_hal::TimeSource` fence |

### EL2 itself, and memory

| module | what |
|---|---|
| [`src/el2.rs`](src/el2.rs) | `HCR_EL2` configuration — claiming the hypervisor level |
| [`src/mmu.rs`](src/mmu.rs) | EL2's **own** stage-1 MMU — identity-mapped, W^X on its image, and (since A2) its DRAM cacheable |
| [`src/cache.rs`](src/cache.rs) | **the one place EL2 knows what a cache line is** — clean / invalidate / clean-invalidate, and why they are not interchangeable |
| [`src/stage2.rs`](src/stage2.rs) | the proven `p2m` → real Stage-2 tables: the refinement, on hardware |

### Guests — lifecycle, scheduling, context

| module | what |
|---|---|
| [`src/guest.rs`](src/guest.rs) | isolation, lifecycle and the scheduler, live — the largest module here |
| [`src/role.rs`](src/role.rs) | which guest, and which of its vCPUs, an index refers to |
| [`src/cell.rs`](src/cell.rs) | the concurrency predicate, made checkable rather than argued |
| [`src/teardown.rs`](src/teardown.rs) | content non-inheritance — the metal's half of "a reborn tenant inherits nothing" |
| [`src/vcpu.rs`](src/vcpu.rs) | a real guest's vCPU context — the state a switch must carry |
| [`src/ctx.rs`](src/ctx.rs) | what a context *component* is, and why forgetting one is a **compile error** |
| [`src/fp.rs`](src/fp.rs) | the FP/SIMD register file, as a context component |
| [`src/pending.rs`](src/pending.rs) | the per-vCPU software pending set — **one type, both switches** |

### Interrupts

| module | what |
|---|---|
| [`src/gic.rs`](src/gic.rs) | the vGIC — hardware GIC virtualization |
| [`src/vgic.rs`](src/vgic.rs) | deploying `hv-vdev`'s emulated GICv3 on *this* machine |

### The guest's devices — none of them real

| module | what |
|---|---|
| [`src/virtio.rs`](src/virtio.rs) | virtio-mmio console — the ring **is** a proven grant |
| [`src/blk.rs`](src/blk.rs) | virtio-blk with copy-on-write template storage |
| [`src/console.rs`](src/console.rs) | the one serial line, multiplexed between guests |
| [`src/vpl011.rs`](src/vpl011.rs) | deploying `hv-vdev`'s emulated PL011 on *this* machine |

### DMA and the SMMU

| module | what |
|---|---|
| [`src/smmu.rs`](src/smmu.rs) | SMMUv3 — closing the DMA window, the stream table, then translation |
| [`src/pcie.rs`](src/pcie.rs) | the minimum config-space access a DMA witness needs |
| [`src/dmawitness.rs`](src/dmawitness.rs) | a **real bus master**, whether the SMMU stops it, and where it lands |

### The consumer's channel

| module | what |
|---|---|
| [`src/observe.rs`](src/observe.rs) | ⚠ `--features observe` — a safety monitor the watched partition **cannot blind**. Demonstrates the flaw first (consent is revocable), then the repair (invert ownership). See [`docs/CONSUMER-CORTENFORGE.md`](../docs/CONSUMER-CORTENFORGE.md) |

### The real-Linux capstone

| module | what |
|---|---|
| [`src/linux.rs`](src/linux.rs) | booting unmodified Linux — device tree, image placement, the handoff |

Not modules, but load-bearing: [`linker.ld`](linker.ld) (load address, `.vectors` alignment, the
stacks, the guest RAM windows), [`build.rs`](build.rs) (wires the linker script in regardless of build
CWD), [`boot-test.sh`](boot-test.sh) (the headless boot gate and **every marker it asserts**), and
[`linux/`](linux/) (the checksum-pinned guest image build).

## The honesty note

A green boot under QEMU attests **functional** behaviour only. What an emulated run does and does
**not** tell you — timing, memory ordering, DMA/IOMMU, errata — is the subject of
[`docs/QEMU-AND-METAL.md`](../docs/QEMU-AND-METAL.md).

★ This is not a formality. `hv-metal` holds **every platform fact as a `const`** and parses no device
tree for itself, so a port begins by measuring what this board actually does —
[`board-probe`](../board-probe/README.md) exists for exactly that, and nothing here has ever run
outside QEMU `virt`.

## The reference

```
cargo doc -p hv-metal --open      # or: cargo xtask metal-lint, which builds it
```

Much of this crate's argument lives in its module docs, and they are the reference — this file is the
front door.
