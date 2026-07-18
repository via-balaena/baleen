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

## Status: M3, Arc 0 — the metal dev + test loop

Per [`docs/ROADMAP.md`](../docs/ROADMAP.md), Arc 0 is the *enabling* step: a bare-metal binary that
boots on the QEMU `virt` machine, prints a marker over the PL011 UART, and parks — establishing the
dev + CI boot-test loop every later arc rides. **No hypervisor logic yet**: EL2 configuration is
Arc 2, the first guest is M4.

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
| `src/main.rs` | `_start` (assembly: stack, `.bss` zero, hand to Rust), `rust_main` (PL011 marker), panic handler |
| `linker.ld` | minimal linker script for the `virt` machine (load at `0x4008_0000`, a 64 KiB stack) |
| `build.rs` | wires the linker script in (works regardless of build CWD) |
| `boot-test.sh` | the headless QEMU boot smoke-test |

## The honesty note

A green boot under QEMU attests **functional** behavior only. What an emulated run does and does
**not** tell you (timing, memory-ordering, DMA/IOMMU, errata) is the subject of
[`docs/QEMU-AND-METAL.md`](../docs/QEMU-AND-METAL.md) — read it before reading isolation into any
QEMU result.
