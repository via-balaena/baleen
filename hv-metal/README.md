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

## Status: M4, Arc 4 — trap-and-service (the proof touches a guest)

Per [`docs/ROADMAP.md`](../docs/ROADMAP.md), Arc 0 stood up the dev + CI boot-test loop; **Arc 1**
turned the raw UART poke into a *proper* PL011 console (`src/pl011.rs`); **Arc 2**
(`src/exceptions.rs`) confirmed `CurrentEL == EL2`, installed `VBAR_EL2` + a 16-entry vector table,
and made a synchronous fault *diagnosable*; **Arc 3** ran the proven brain on the bare CPU — configure
`HCR_EL2.RW=1` (`src/el2.rs`), realize `hv_hal::TimeSource` on the generic timer (`CNTPCT_EL0`,
`src/time.rs`), supply a `#[global_allocator]` (`src/heap.rs`), and dispatch a synthetic `HvCall`
(`dom0 CreditGrant(100)`) through the *actual* `Hypervisor::dispatch` → `balance=100` (audited as the
`hv-hal` fence in [`docs/AUDIT-1-HAL-FENCE.md`](../docs/AUDIT-1-HAL-FENCE.md), **Architecture Audit #1**).

**Arc 4** ([`src/guest.rs`](src/guest.rs)) is where the proof first touches a **guest**:

- **A trivial EL1 guest** — a `.rodata` instruction template the hypervisor copies into a reserved
  guest RAM window and `eret`s to. Its only job: issue `HVC`s and let the result be observed.
- **A minimal Stage-2** — `HCR_EL2.VM=1` + a single 2 MiB identity block (one L1 table → one L2
  block, 4 KiB granule, 39-bit IPA) mapping *only* the guest's RAM; `VTCR_EL2`/`VTTBR_EL2`
  spec-derived and blind-audited. *Just enough to run the guest* — not the model's `p2m` (Arc 5).
- **Trap-and-service** — the guest's `HVC` traps to EL2 (vector slot 8, `EC=0x16`). A GPR
  save/restore frame on a **dedicated exception stack** (+ a re-entry guard) — the resume machinery
  Arc 2's diagnostic handler deferred — saves `x0..x30`; the saved registers are decoded through
  `hv-core`'s `RawHypercall`/`Hypercall::decode` seam, mapped to an `HvCall`, and routed through the
  **actual `Hypervisor::dispatch`**; the result is written back into the guest's `x0` and `eret`ed.
- **The guest observes it** — `grant 100` → 100, `spend 30` → **70**; the guest echoes 70 in a final
  `HVC` and the hypervisor asserts it equals the balance it served. 70 is no call's input and takes
  two resume cycles to reach, so the round trip is a witness *produced by the guest*.
- **`VcpuOps::set_entry` realized on ARM** (`ELR_EL2`); `inject_interrupt` (no GIC) and `GuestMemory`
  (register-passed args) honestly deferred with assumptions named.

It **refines** the proof (the model's dispatch, driven for a real guest) and is QEMU-sound for the
functional round trip — **no isolation content**: the faithful `p2m`→Stage-2 refinement and the
negative-isolation test are **Arc 5** (Architecture Audit #2). Full write-up + the M4 HAL ledger:
[`docs/ARC-4-TRAP-AND-SERVICE.md`](../docs/ARC-4-TRAP-AND-SERVICE.md).

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
| `src/main.rs` | `_start` (assembly: boot-CPU gate, stack, `.bss` zero, hand to Rust), `rust_main` (console up, EL2 confirm, install vectors, configure `HCR_EL2`, timer witness, dispatch a synthetic `HvCall` into `hv-core`, then **enter the EL1 guest**), panic handler (reports `PanicInfo`) |
| `src/guest.rs` | **Arc 4 trap-and-service** — the trivial guest, minimal Stage-2, `ArmVcpu`/`VcpuOps`, the `eret` into EL1, the slot-8 GPR save/restore trampoline + handler (decode → `Hypervisor::dispatch` → result), the round-trip witness |
| `src/pl011.rs` | the PL011 UART driver — init, TX-FIFO-gated writes, `core::fmt::Write` |
| `src/exceptions.rs` | EL2 confirm (`CurrentEL`), `VBAR_EL2` + the 16-entry vector table (slot 8 → the guest trampoline), the `ESR`-decoding diagnostic handler |
| `src/el2.rs` | `HCR_EL2` configuration (`RW=1`, minimal) + read-back confirm |
| `src/time.rs` | the ARM generic-timer `hv-hal::TimeSource` (`CNTPCT_EL0`, `isb`-ordered) + the boot monotonicity witness |
| `src/heap.rs` | the `#[global_allocator]` — a bump allocator over a `.bss` arena, so `hv-core`'s `alloc` links |
| `linker.ld` | minimal linker script for the `virt` machine (load at `0x4008_0000`, a 2 KiB-aligned `.vectors` section, a 64 KiB stack, a 16 KiB exception stack, and a 2 MiB-aligned guest RAM window) |
| `build.rs` | wires the linker script in (works regardless of build CWD) |
| `boot-test.sh` | the headless QEMU boot smoke-test (default + `selftest` builds) |

## The honesty note

A green boot under QEMU attests **functional** behavior only. What an emulated run does and does
**not** tell you (timing, memory-ordering, DMA/IOMMU, errata) is the subject of
[`docs/QEMU-AND-METAL.md`](../docs/QEMU-AND-METAL.md) — read it before reading isolation into any
QEMU result.
