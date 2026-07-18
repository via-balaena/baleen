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

## Status: M3, Arc 2 — EL2 + exception vectors

Per [`docs/ROADMAP.md`](../docs/ROADMAP.md), Arc 0 stood up the dev + CI boot-test loop with a raw
one-byte UART poke; **Arc 1** turned that into a *proper* PL011 console (`src/pl011.rs`): it
initializes the UART into a known state (8N1, FIFOs on, TX enabled), gates every write on the
TX-FIFO-not-full flag so output cannot be silently dropped, and exposes `core::fmt::Write` so later
arcs can `write!`/`writeln!` formatted diagnostics — the substrate everything downstream reports
through.

**Arc 2** (`src/exceptions.rs`) makes a fault *diagnosable*: it confirms `CurrentEL == EL2`, installs
`VBAR_EL2` pointing at a 2 KiB-aligned 16-entry AArch64 vector table, and stands up a default handler
that decodes any synchronous fault (`EC`/`ELR`/`FAR`/`ESR`) and reports it through the Arc-1 console
before halting — instead of triple-faulting into a silent reset loop. A feature-gated `selftest` build
fires `BRK #0` so the boot-test can assert the vectors actually catch and decode the fault
(`vector=4`, `EC=0x3c`).

It is **plumbing** — EL2 configuration + diagnostics with no isolation content — and **still no
hypervisor logic**: linking `hv-core` and dispatching a synthetic `HvCall` is Arc 3, the first guest
is M4. A green boot attests the console, EL2 readout, and `ESR` decode work, nothing about the
hypervisor.

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
| `src/main.rs` | `_start` (assembly: boot-CPU gate, stack, `.bss` zero, hand to Rust), `rust_main` (console up, EL2 confirm, install vectors, banner), panic handler (reports `PanicInfo`) |
| `src/pl011.rs` | the PL011 UART driver — init, TX-FIFO-gated writes, `core::fmt::Write` |
| `src/exceptions.rs` | EL2 confirm (`CurrentEL`), `VBAR_EL2` + the 16-entry vector table, the `ESR`-decoding default handler |
| `linker.ld` | minimal linker script for the `virt` machine (load at `0x4008_0000`, a 2 KiB-aligned `.vectors` section, a 64 KiB stack) |
| `build.rs` | wires the linker script in (works regardless of build CWD) |
| `boot-test.sh` | the headless QEMU boot smoke-test (default + `selftest` builds) |

## The honesty note

A green boot under QEMU attests **functional** behavior only. What an emulated run does and does
**not** tell you (timing, memory-ordering, DMA/IOMMU, errata) is the subject of
[`docs/QEMU-AND-METAL.md`](../docs/QEMU-AND-METAL.md) — read it before reading isolation into any
QEMU result.
