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

| crate           | what it is                                                                            | status |
| --------------- | ------------------------------------------------------------------------------------- | ------ |
| `hv-hal`        | the *southbound* fence: hardware traits (`GuestMemory`, `TimeSource`, `VcpuOps`)       | ✅ M1  |
| `hv-core`       | all logic as a `no_std` library, zero `unsafe`: dispatch and state machines           | ✅ M1  |
| `hv-sim`        | host harness — fake memory, hand-cranked clock, seeded deterministic simulation       | ✅ M1  |
| `hv-metal`      | bare-metal binary: boot, VMX, the thin fenced `unsafe` core                           | ⏳ M3  |
| `hv-fuzz`       | `cargo-fuzz` targets against the hypercall dispatcher                                  | ⏳ M2  |
| `baleen-xenabi` | a *northbound* **personality**: translates Xen's wire ABI into neutral `hv-core` ops  | ⏳ M5  |
| `xtask`         | build/test automation (`cargo xtask <task>`)                                          | ✅ M1  |

`hv-metal`, `hv-fuzz`, and `baleen-xenabi` are intentionally absent from the
workspace until their milestones — the first two need a custom target / nightly,
and the third only takes shape once M5 forces a real guest ABI.

### Identity vs. personality

`hv-core` does not know what Xen is. Schedulers, event-channel state machines,
memory accounting, and grant-style resource lifecycles are *generic* hypervisor
logic. Xen's specific hypercall numbering, ABI structs, and PVH boot protocol live
in a **personality** — `baleen-xenabi` — that sits northbound of the core in the
same architectural position `hv-hal` sits southbound. Xen is a conformance target
and a compatibility layer one of our markets needs, **not** the identity of the
core:

- **Qubes wedge** needs the Xen personality faithful (libxl-ish tooling, event
  channels, grant tables, xenstore) — this is where the clean-room, ABI-as-spec,
  XTF-conformance discipline applies in full. See [`CLEANROOM.md`](CLEANROOM.md).
- **Automotive / static-partitioning wedge** has zero Xen legacy — it gets a thin
  native personality or virtio-only guest interfaces, and never links Xen at all.

## The architecture in one picture

The core is sandwiched between two thin translation layers. Both are *personalities*
of a sort — one faces guests, one faces hardware — and neither leaks into the core.

```
   NORTHBOUND — guest ABI (personality, not identity)
         ┌──────────────────┐   ┌────────────────────────┐
         │ baleen-xenabi    │   │ baleen-virtio / native │
         │ Xen wire → ops   │   │ automotive wedge       │
         │  — M5 —          │   │  — later —             │
         └────────┬─────────┘   └───────────┬────────────┘
                  │      neutral, ABI-agnostic ops
          ┌───────▼────────────────────────▼─────────────┐
          │  hv-core   (no_std, zero unsafe)              │
          │  scheduler · event channels · grant table     │
          │  dispatch · invariants — knows no personality │
          └───────────────────┬──────────────────────────┘
                              │  speaks ONLY through
                     ┌────────┴────────┐  hv-hal traits
                     │                 │
         ┌───────────▼──────┐   ┌──────▼─────────────────┐
         │ hv-sim (host)    │   │ hv-metal (bare metal)  │
         │ Vec<u8> memory   │   │ real page tables, VMX  │
         │ manual clock     │   │ the thin unsafe core   │
         │ deterministic    │   │  — M3 —                │
         └──────────────────┘   └────────────────────────┘
   SOUTHBOUND — hardware (the fence)
```

The southbound fence between core and hardware is the *same* fence as the `unsafe`
boundary. ~85% of bugs live in `hv-core` and are found on your laptop; the two
translation layers are each small enough to audit line by line (that's what the
hardware — and, northbound, XTF conformance — is for).

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
- **M2** *(landed)*: the two historically XSA-prone subsystems, each as a pure,
  whole-system state machine with invariants checked on every transition,
  property-tested (`hv-core`), seeded-simulated (`hv-sim`), and fuzzed (`hv-fuzz`):
  - `hv-core::evtchn` — event channels (interdomain / VIRQ / IPI ports), guarding
    interdomain **reciprocity**, VIRQ uniqueness, and no-signal-on-free.
  - `hv-core::grant` — grant tables (grant / end / map / unmap / copy), guarding the
    core safety rule that **a grant with a live mapping cannot be ended**, plus
    refcount consistency and read-only integrity.

  Both are generic and ABI-agnostic — wire formats (the `shared_info` bitmaps, the
  `grant_entry` structs) stay in the M5 personality. Clean-room provenance discipline
  is live here, the first time Xen behavior informs a core design — see
  [`CLEANROOM.md`](CLEANROOM.md).
- **M3**: `hv-metal` boots on real hardware to a serial "hello" and enters VMX root
  mode. The first `unsafe`, weeks in rather than day one.
- **M4**: one hardware-backed vCPU running a trivial guest; VMEXITs translated into
  `hv-core` calls. The fence becomes real and load-bearing.
- **M5**: PVH Linux boot — the vertical slice. The Xen **personality**
  (`baleen-xenabi`) enters here: PVH boot forces speaking Xen's ABI for real, so
  this is where clean-room, ABI-as-spec, XTF-conformance discipline goes into full
  force — and, conveniently, the part with legal-hygiene requirements is the part
  built last.

## License

Dual-licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at
your option.
