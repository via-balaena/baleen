<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# The consumer: CortenForge, and what it requires of Baleen

> **What this document is.** A derivation of what a *named* consumer would require of
> Baleen, checked line by line against what the code already does. It exists because
> several items on this project's ledger are deferred with the words *"for want of a
> consumer"*, and until now that was literally true: nothing outside this repository
> was going to run on it.
>
> **What this document is not.** A commitment, a schedule, or a scope. Nothing here is
> queued. It is the input a rung gets scoped *from*, and its most useful output is the
> two places where the consumer's requirements **collide with a property this project
> has already proved** — because those are design questions, not backlog items.

## The consumer

**CortenForge** is a differentiable simulation SDK for mechatronics whose capstone is a
person-specific, RL-controlled **exoskeleton**. It is a separate repository and is not a
dependency of anything here.

The relevant artifact is not the SDK. It is the SDK's **output**: a trained control
policy, running on the device that the exoskeleton *is*.

### The role, stated precisely

A powered exoskeleton worn by a person is a **mixed-criticality** system. It carries a
learned control policy that cannot be trusted by construction — its behaviour is a
consequence of training, not of proof — alongside a safety monitor whose envelope must
hold regardless of what the policy does. The standard architecture for that pairing is
runtime assurance: put them in separate partitions and make the isolation a property of
the hardware rather than of the software's good behaviour.

That is the shape Baleen already has. The characteristics recorded elsewhere in these
docs as *limitations* — two compile-time guests (`hv-metal/src/linux.rs`'s `NUM_GUESTS`),
no dynamic configuration, no toolstack — are **requirements** in this role, not gaps.

### ⛔ The role this is NOT, recorded so it is not re-proposed

A prior framing had Baleen hosting CortenForge *simulation* workloads on high-core-count
machines. It was refuted, and the reasons are structural rather than matters of effort:

* A hypervisor does not make cores faster; isolation is not the bottleneck for a
  simulation tenant and is not what one would pay for.
* Firecracker already serves that role, on both x86 and AArch64, at scale.
* Baleen schedules onto **one physical CPU**. Lifting that is the change that would
  invalidate the single-core reasoning the model's proofs rest on.
* The binding constraint on that workload is memory bandwidth, which a hypervisor
  cannot improve.

The consumer here is the **device**, not the datacentre.

## ★ The finding: the requirement collides with the thesis

The safety monitor must **observe** the policy partition — its commanded torques, its
liveness — or it is not a monitor. That is a channel between two guests.

Baleen's metal currently asserts, in `hv-metal/src/guest.rs`, that no such channel
exists:

```
no_channel = no_grant && no_evtchn && no_foreign_link && no_control
```

and the surrounding comment is explicit about what that buys: it is the **precondition**
of the model's Tier-D non-interference theorem, `¬(vault ⇝ disposable)` over the model's
authorization relation. See [`AUDIT-3-NON-INTERFERENCE.md`](AUDIT-3-NON-INTERFERENCE.md)
and [`TIER-D-NONINTERFERENCE.md`](TIER-D-NONINTERFERENCE.md).

So the requirement is **not** "build inter-partition communication". The mechanism
already exists and is exercised on the metal: `hv-metal/src/guest.rs` routes timer VIRQ
injection through `hv-core`'s proven event channels (`hv-core/src/evtchn.rs`), dispatches
`HvCall::GrantAccess` and `HvCall::CreditGrant`, and `hv-metal/src/virtio.rs` gates its
backend on `hv-core/src/grant.rs`'s authorization. The absence of a channel between the
two guests is a **deliberate configuration**, and a theorem depends on it.

The real question is therefore sharper, and it is the interesting one:

> **Can a one-way, authorized observation channel be introduced such that the model
> proves the weakening is exactly what was intended and no more?**

That is a verification question of the kind this project is built for — the model already
distinguishes an authorizing edge from its absence, so "monitor may observe policy, policy
may not observe or affect monitor" is expressible in the vocabulary that already exists.
⚠ It is also the point at which the isolation headline stops being *"no channel"* and
becomes *"exactly one channel, in one direction, and here is the proof"*. **That is a
strictly harder claim to make and a strictly more useful one.** It should not be
attempted as a side effect of some other rung.

## The requirement table

Each row is checked against the code, not against impression. "Evidence" cites where the
answer was read.

| requirement of the role | state | evidence |
| --- | --- | --- |
| AArch64 / EL2, type-1, static partitioning | ✅ by design | the whole of `hv-metal` |
| Two isolated guests, fixed at build time | ✅ | `hv-metal/src/linux.rs`, `hv-metal/src/role.rs` |
| Unmodified Linux in a partition | ✅ demonstrated | [`ARC6B-LINUX-ON-THE-PROVEN-EMITTER.md`](ARC6B-LINUX-ON-THE-PROVEN-EMITTER.md) |
| Stage-2 isolation, machine-checked | ✅ proven | [`AUDIT-2-P2M-STAGE2.md`](AUDIT-2-P2M-STAGE2.md), [`STAGE2-REFINEMENT-FORALL-N.md`](STAGE2-REFINEMENT-FORALL-N.md) |
| DMA confinement for assigned devices | ✅ | [`SMMU-DEVICE-PATH-COMPOSITION.md`](SMMU-DEVICE-PATH-COMPOSITION.md), `hv-metal/src/smmu.rs` |
| Hypervisor self-protection (W^X, own MMU) | ✅ | `hv-metal/src/mmu.rs`, `hv-metal/src/cache.rs` |
| **Authorized monitor → policy observation** | ⚠ **collides with the thesis** — see above | `hv-metal/src/guest.rs` |
| **Bounded scheduling latency for the monitor** | ⚠ unanalyzed | `hv-core/src/sched.rs`, driven from `hv-metal/src/role.rs` |
| **Actuator / sensor I/O reaching a guest** | ⚠ groundwork only; no real device is driven | `hv-metal/src/smmu.rs` |
| **A non-Linux (small) monitor partition** | ⚠ unknown — never attempted | — |
| Real silicon | ⛔ never run outside QEMU | [`QEMU-AND-METAL.md`](QEMU-AND-METAL.md) |
| SMP | ⛔ **not wanted** — see below | — |

⚠ **The `no_std` question was checked and came back the other way.** A bare-metal
partition running CortenForge code directly is not available: its layer-0 crates declare
no `#![no_std]`, and the portability gate they do carry is a `--no-default-features`
check against `wasm32-unknown-unknown`, which is not a freestanding target. **The policy
partition is therefore a Linux guest** — which is what Baleen already boots, so this
costs nothing. It is recorded because the opposite was assumed before it was checked.

⛔ **SMP stays off the list deliberately.** It is the one requirement that would be
answered by making the proofs weaker rather than the machine better, and the role does
not obviously need it: a monitor and a policy are two partitions, not two hundred.

## What a named consumer unlocks

Several ledger items are parked on the absence of exactly this. With a consumer named,
they become answerable questions rather than speculation — **not automatically worth
doing, but no longer un-scopeable**:

* **III-2, the `u8` SPI ceiling.** Parked "for want of a consumer". A device partition
  driving real actuators is the first thing that would plausibly need SPI identifiers
  above 255.
* **Ledger 2(e)** — a device assignment to a domain with no emitted Stage-2 image.
  Parked because "there is no guest-driven control domain". A monitor partition is
  precisely a control domain, though it need not be guest-driven.
* **The pending/active residue.** Parked because "the shipped kernel never reads it". A
  small non-Linux monitor is a guest that might.

★ **The point is not that these should now be built.** It is that this project spent a
session concluding it had *no next move*, when what it actually had was no consumer. The
rung sources in the roadmap are unchanged; this document adds an input to the first of
them.

## What this changes about the board

The recorded hardware decision selects a **cheap dev-board, not server-class**, and
weighs three items a board would buy. Those criteria were derived for a *generic port* —
whether the board hands you EL2, whether a cloud instance could substitute, whether
there is serial console access. `board-probe/` (see [`board-probe/README.md`](../board-probe/README.md))
is built against exactly those.

The role above adds criteria that the generic port never had to consider: real-time
behaviour under load, actuator and sensor I/O, and a power and size envelope compatible
with something worn. **A board bought against the generic criteria may be the wrong board
for the consumer**, and the two lists have not been reconciled.

⚠ **This is an argument for deriving the criteria before the purchase, not for delaying
indefinitely.** Phase 0 remains what it was: run `board-probe` on a real board before
scoping any port.

## What is deliberately NOT decided here

* **Whether to build the observation channel.** It is the strongest candidate this
  document produces and it is also the one that touches a proved property. It needs its
  own scope.
* **Any schedule.** CortenForge's capstone is years out and is not gated on Baleen.
* **That Baleen is on the exoskeleton's critical path.** It is not. This describes a
  destination that makes the two projects coherent; it does not make either depend on
  the other. If the destination is never reached, everything Baleen has proved is
  unaffected — which is the correct amount of coupling for a document written this
  early.
