<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Baleen

A type-1 hypervisor written in Rust, built brain-first.

The usual hypervisor project starts with boot assembly and rewards you with a
silent hang. Baleen inverts that. The hypervisor is structured as a **library of
pure logic** that never touches hardware directly — it speaks only to a small set
of traits (the *fence*). That library is driven, unit-tested, fuzzed, and
**deterministically simulated on a laptop** with `cargo test`. Hardware is deferred
until there is a tested brain to plug in.

The payoff: green CI in week one, and you are never more than a day from a passing
test on a multi-year solo project.

## Workspace

| crate      | what it is                                                            | status |
| ---------- | -------------------------------------------------------------------- | ------ |
| `hv-hal`   | the fence: trait definitions (`GuestMemory`, `TimeSource`, `VcpuOps`) | ✅ M1  |
| `hv-core`  | all logic as a `no_std` library, zero `unsafe`: hypercall dispatch and state machines | ✅ M1 |
| `hv-sim`   | host harness — fake memory, hand-cranked clock, seeded deterministic simulation | ✅ M1 |
| `hv-metal` | bare-metal binary: boot, VMX, the thin fenced `unsafe` core           | ⏳ M3  |
| `hv-fuzz`  | `cargo-fuzz` targets against the hypercall dispatcher                  | ⏳ M2  |
| `xtask`    | build/test automation (`cargo xtask <task>`)                          | ✅ M1  |

`hv-metal` and `hv-fuzz` are intentionally absent from the workspace until their
milestones — they need a custom target / nightly and would break `cargo test`.

## The architecture in one picture

```
          ┌──────────────────────────────────────────┐
          │  hv-core   (no_std, zero unsafe)          │
          │  scheduler · event channels · grant table │
          │  hypercall dispatch · invariants          │
          └───────────────────┬──────────────────────┘
                              │  speaks ONLY through
                     ┌────────┴────────┐  hv-hal traits
                     │                 │
         ┌───────────▼──────┐   ┌──────▼─────────────────┐
         │ hv-sim (host)    │   │ hv-metal (bare metal)  │
         │ Vec<u8> memory   │   │ real page tables, VMX  │
         │ manual clock     │   │ the thin unsafe core   │
         │ deterministic    │   │  — M3 —                │
         └──────────────────┘   └────────────────────────┘
```

The fence between core and hardware is the *same* fence as the `unsafe` boundary.
~85% of bugs live in `hv-core` and are found on your laptop; the remaining
translation layer is small enough to audit line by line (that's what the hardware
is for).

## Try it

```sh
cargo test --workspace     # or: cargo xtask test
```

M1's headline test runs `hv-core` through 10,000 seeded interleavings of the toy
credit-account state machine, checking its conservation invariant on every
transition. Same seed → same run, exactly — so any future invariant break is a
one-line regression test, not a Heisenbug.

## Milestones

- **M1 — architecture proof** *(this commit)*: `hv-core` dispatches two toy
  hypercalls, driven entirely by `hv-sim` with deterministic seeded replay. No
  hardware, no asm.
- **M2**: event channels as a pure state machine — property-tested and fuzzed.
- **M3**: `hv-metal` boots on real hardware to a serial "hello" and enters VMX root
  mode. The first `unsafe`, weeks in rather than day one.
- **M4**: one hardware-backed vCPU running a trivial guest; VMEXITs translated into
  `hv-core` calls. The fence becomes real and load-bearing.
- **M5**: PVH Linux boot — the vertical slice.

## License

Dual-licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at
your option.
