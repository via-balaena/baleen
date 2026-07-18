<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `hv-metal` — the bare-metal layer (AArch64 / EL2)

The southbound metal layer beneath the proven `hv-core` brain: boot, enter EL2, and (as later
arcs land) drive real guests. This is the **one crate that carries `unsafe`** — the workspace
forbids it everywhere else — because the metal is where MMIO, system registers, and page tables
live. Everything above it stays `unsafe`-free and proven.

It is a **standalone crate** (its own `[workspace]`), **excluded** from the parent workspace: it
targets `aarch64-unknown-none-softfloat` and cannot link for the host, so stable `cargo test
--workspace` never touches it. It is built and booted out-of-band.

## Status: M3, Arc 3 — the proven brain runs on the metal

Per [`docs/ROADMAP.md`](../docs/ROADMAP.md), Arc 0 stood up the dev + CI boot-test loop; **Arc 1**
turned the raw UART poke into a *proper* PL011 console (`src/pl011.rs`, 8N1 + FIFO, TX-gated writes,
`core::fmt::Write`); **Arc 2** (`src/exceptions.rs`) confirmed `CurrentEL == EL2`, installed
`VBAR_EL2` + a 16-entry vector table, and made a synchronous fault *diagnosable* (decode `EC`/`ELR`/
`FAR`/`ESR` and report, instead of triple-faulting) — a feature-gated `BRK #0` self-test asserts the
vectors fire (`vector=4`, `EC=0x3c`).

**Arc 3** is where the proven brain first runs on the bare CPU:

- **`HCR_EL2.RW=1`** (`src/el2.rs`) — configure EL2 for AArch64 lower-EL operation, full-register
  write (reset is UNKNOWN), read back and confirm. No guest-trap bits (`VM`/`TGE`/`IMO`…) — those are
  M4, when there is a guest to trap.
- **`TimeSource` on the generic timer** (`src/time.rs`) — realize the `hv-hal` fence's clock over
  `CNTPCT_EL0`, `isb`-ordered against speculative reordering (a per-mechanism QEMU-vs-metal line);
  the boot witnesses the count is monotonic and live.
- **A `#[global_allocator]`** (`src/heap.rs`) — a bump allocator over a `.bss` arena, so `hv-core`'s
  `alloc` use links on the metal.
- **The brain, dispatched** — link `hv-core`, construct a real `Hypervisor`, and dispatch a synthetic
  `HvCall` (`dom0` `CreditGrant(100)`) through the *actual* `Hypervisor::dispatch` path, printing
  `balance=100`. The `selftest` build asserts a two-call accounting witness (grant 100 / spend 30 →
  70) before the Arc-2 `BRK` check.

It **refines** the proof (the HAL realizes the model's southbound assumptions) and is QEMU-sound for
the functional dispatch — **still pre-guest**: no EL1 guest, no Stage-2, no isolation content (M4).
The fence itself is audited in [`docs/AUDIT-1-HAL-FENCE.md`](../docs/AUDIT-1-HAL-FENCE.md)
(**Architecture Audit #1**): the `hv-hal` surface is architecture-neutral, `TimeSource` is realized
and honored on ARM, `GuestMemory`/`VcpuOps` are deferred to M4 with assumptions named.

## Build & run

```sh
rustup target add aarch64-unknown-none-softfloat   # once
cargo xtask qemu        # build + boot interactively under QEMU (Ctrl-A X to quit)
cargo xtask qemu-test   # headless boot smoke-test (asserts the serial marker) — the CI check
```

`cargo xtask qemu-test` runs [`boot-test.sh`](boot-test.sh), which boots the image under
`qemu-system-aarch64 -M virt,virtualization=on -cpu max` and asserts `rust_main`'s marker appears
on the serial console. CI runs exactly this (`.github/workflows/ci.yml`, the *metal boot (QEMU)*
job).

## Layout

| file | what |
|---|---|
| `src/main.rs` | `_start` (assembly: boot-CPU gate, stack, `.bss` zero, hand to Rust), `rust_main` (console up, EL2 confirm, install vectors, configure `HCR_EL2`, timer witness, **dispatch a synthetic `HvCall` into `hv-core`**), panic handler (reports `PanicInfo`) |
| `src/pl011.rs` | the PL011 UART driver — init, TX-FIFO-gated writes, `core::fmt::Write` |
| `src/exceptions.rs` | EL2 confirm (`CurrentEL`), `VBAR_EL2` + the 16-entry vector table, the `ESR`-decoding default handler |
| `src/el2.rs` | `HCR_EL2` configuration (`RW=1`, minimal) + read-back confirm |
| `src/time.rs` | the ARM generic-timer `hv-hal::TimeSource` (`CNTPCT_EL0`, `isb`-ordered) + the boot monotonicity witness |
| `src/heap.rs` | the `#[global_allocator]` — a bump allocator over a `.bss` arena, so `hv-core`'s `alloc` links |
| `linker.ld` | minimal linker script for the `virt` machine (load at `0x4008_0000`, a 2 KiB-aligned `.vectors` section, a 64 KiB stack) |
| `build.rs` | wires the linker script in (works regardless of build CWD) |
| `boot-test.sh` | the headless QEMU boot smoke-test (default + `selftest` builds) |

## The honesty note

A green boot under QEMU attests **functional** behavior only. What an emulated run does and does
**not** tell you (timing, memory-ordering, DMA/IOMMU, errata) is the subject of
[`docs/QEMU-AND-METAL.md`](../docs/QEMU-AND-METAL.md) — read it before reading isolation into any
QEMU result.
