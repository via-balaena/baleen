<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Baleen

[![CI](https://github.com/via-balaena/baleen/actions/workflows/ci.yml/badge.svg)](https://github.com/via-balaena/baleen/actions/workflows/ci.yml)

A type-1 hypervisor written in Rust, built brain-first.

The usual hypervisor project starts with boot assembly and rewards you with a
silent hang. Baleen inverts that. The hypervisor is structured as a **library of
pure logic** that never touches hardware directly — it speaks only to a small set
of traits (the *fence*). That library is driven, unit-tested, fuzzed, and
**deterministically simulated on a laptop** with `cargo test`. Hardware is deferred
until there is a tested brain to plug in.

The payoff: green CI in week one, and you are never more than a day from a passing
test on a multi-year solo project.

> **On the name.** "Baleen" is an interim working name. The `baleen` crate name on
> crates.io is currently held by an unrelated placeholder, so the eventual published
> binary may ship under a different crate name; the project identity is the
> `via-balaena/baleen` repository. The internal library crates (`hv-*`) are marked
> `publish = false` and are not intended for crates.io.

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
          │  sched · evtchn · grant · page-type accounting│
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
  - `hv-core::sched` — the scheduler (admit / run / preempt / block / wake / offline)
    over a fixed set of physical CPUs, guarding **pCPU exclusivity by reciprocity**
    (a vCPU is `Running{pcpu}` iff that CPU names it back) plus monotonic per-vCPU
    time accounting. Mechanism only — scheduling *policy* stays above the core.
  - `hv-core::Hypervisor` — the integrated core: per-domain credit plus all three
    subsystems behind one typed, ABI-neutral `HvCall` dispatch. `hv-sim` drives the
    whole thing through one seam, and one `invariants_hold()` covers the lot. This is
    the real dispatch seam the M5 personality will decode wire-format calls into.

  All of it is generic and ABI-agnostic — wire formats (the `shared_info` bitmaps, the
  `grant_entry` structs) stay in the M5 personality. Clean-room provenance discipline
  is live here, the first time Xen behavior informs a core design — see
  [`CLEANROOM.md`](CLEANROOM.md).
- **Scheduling policy** *(landed)*: `hv-core::policy` — the layer that *picks*, above
  the dispatch seam (a guest never asks to be scheduled; the tick/idle path does). A
  work-conserving, weighted-proportional-fair policy that runs the least-serviced-
  per-weight vCPU and time-slices with a quantum, enacting only through the
  mechanism's public transitions. **Wake-boost** places a vCPU re-entering the
  runnable pool (from `Blocked`, or freshly admitted) at the pool's floor, so a
  long-slept vCPU can't monopolise a CPU to "catch up" and starve the ones that stayed
  runnable — the scheduler's version of CFS's `place_entity`. Unlike a state machine
  it has no safety invariant — a bad policy is unfair, not unsafe — so it is held to
  *properties* instead: work-conservation, proportional fairness, starvation-freedom,
  and sleeper fairness, all property-tested (`hv-sim`) and fuzzed (`hv-fuzz`).
- **Page-type accounting** *(landed)*: `hv-core::p2m` — a fourth whole-system state
  machine, Xen's third historical XSA factory after event channels and grant tables.
  Every machine frame carries an existence reference count and two typed counts
  (allocate / get / put / get_type / put_type / free); the safety invariant is
  **write-xor-pagetable** — `get_type` refuses a writable reference while a page-table
  reference is live and vice-versa, so a frame is never usable as both writable memory
  and a page table at once (the exact shape of the `PGT_*` typecount bugs that let a
  guest forge a PTE and escape). Reference coherence (typed ≤ total) and owner
  integrity ride alongside; a frame can only be freed once nothing references it. The
  reference-moving primitives are *internal* — the guest-facing surface is only allocate
  and free, because a raw "drop a reference" hypercall would let one domain release a
  reference another holds; every acquire is balanced by exactly one release, gated on
  proof of the acquire, which is how a scalar count stays sound (as in Xen). Folded into
  the integrated `invariants_hold()`, property-tested (`hv-core`), seeded-simulated
  (`hv-sim`), and fuzzed (`hv-fuzz`) — the seventh fuzz target. This brings `hv-core`'s
  pure brain to **four** whole-system state machines, credit accounting, and a
  scheduling policy over them — all green on a laptop before any hardware exists.
- **Grant ↔ page-type seam** *(landed)*: the first invariant that spans *two*
  subsystems. Grant tables and page-type accounting describe the same physical pages,
  so a grant map now takes a real page reference through the seam — a **writable** map
  pins the frame's writable type (it can never simultaneously be a page table); a
  **read-only** map takes an existence reference only (a reader is type-agnostic). This
  closes the gap *between* the subsystems: the owner can no longer free or re-type a
  frame while a foreign domain maps it — the cross-domain use-after-free / type-confusion
  XSA shape. A stale grant (frame freed and reallocated after granting) is refused at map
  time by re-checking ownership, closing a confused-deputy hole. A cross-subsystem
  invariant — every live mapping is owned and backed by matching references — is
  debug-asserted after every dispatch and holds across 10k seeds. Subsystems stay pure
  and mutually ignorant; the `Hypervisor` owns the join.
- **Page-table pin/unpin** *(landed)*: `P2mPin`/`P2mUnpin` (Xen's `MMUEXT_PIN_TABLE`) —
  the operation that turns one of a domain's own frames into a page table, holding a
  persistent page-table type reference until unpinned. This is what finally makes the
  **write-xor-pagetable** invariant reachable end-to-end through the dispatch seam: pin a
  frame, and a foreign domain's *writable* grant map of it is refused (`TypePinned`) with
  the grant map rolled back; conversely a writably-mapped frame cannot be pinned — so a
  page is never a page table and writable at once, the exact escape (guest forges a PTE)
  the whole `p2m` module exists to prevent. Unlike the raw type primitives, pin/unpin are
  guest-facing and *sound*: owner-gated, and balanced by a pin bit (unpin proves a prior
  pin), the second consumer of the "release gated on proof of acquire" discipline. This
  completes the page-type foundation — both halves of the exclusivity are now produced by
  real guest operations and exercised across the seed space and fuzzers.
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
