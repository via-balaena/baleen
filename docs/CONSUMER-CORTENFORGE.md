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
> place where the consumer's requirements **collide with a property this project has
> already proved** — because that is a design question, not a backlog item.
>
> ⚠ This sentence first read *"the **two** places"*, and there is **one**. The other ⚠
> rows below are gaps — unanalyzed, or never attempted — which is a different and much
> cheaper thing than a collision with a theorem. Corrected rather than quietly reworded,
> because a count asserted in a header is exactly the kind this project keeps writing
> wrong (#276, #281–#284).

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

That is a verification question of the kind this project is built for, and the model's
existing vocabulary already reaches it. Both halves of "one-way, observation-only" are
expressible today, in `hv-core/src/hypervisor.rs`:

* **Direction** — `controls(&self, holder: DomId, target: DomId)` is directional by
  signature, and `hv-metal/src/guest.rs` already tests the two orderings separately.
* **Observation without influence** — `hv-core/src/grant.rs`'s authorization carries a
  `writable` permission bit, so permission is expressible per-direction.

⚠⚠ **This bullet first concluded that "a **read-only** grant is the natural shape of *the monitor
may read the policy's output and may not alter it*". That is the WRONG DIRECTION, and two facts in
the code say so** — recorded here because the appealing answer was the wrong one:

1. **A grant is not one-way.** `obs(a)` carries *"grant table rows **and their live-map counts**"*
   (`hv-sim/src/noninterference.rs`), and the consent channel authorizes the grantee to move
   them. So **the act of observing is visible to the observed** — a reverse channel, and one that
   lets a learned policy detect that it is being monitored, which is the precise failure runtime
   assurance exists to prevent.
2. **Consent is the wrong model for an adversarial tenant.** If the policy owns the frame it must
   *offer* the grant, and `end_access` refuses with `InUse` **only while a mapping is held** — a
   copy holds none. **The untrusted policy could revoke at will and blind its own monitor.**

**The repair is to invert ownership: the monitor owns the telemetry page**, offers the policy
writable access, and reads its own memory with no hypercall. The read then cannot be revoked,
because access to one's own page is not revocable. The trade — the policy can *corrupt* that page —
is accepted deliberately: the contents are the untrusted partition's own claims and were never
trustworthy, while a **blinded** monitor is a safety failure. *Trust the channel's existence, never
its contents.*

⚠ Introducing that channel is the point at which the isolation headline stops being
*"no channel"* and becomes *"exactly one channel, in one direction, and here is the
proof"*. **That is a strictly harder claim to make and a strictly more useful one.** It
should not be attempted as a side effect of some other rung.

⚠⚠ **CORRECTION (2026-08-10, same day, forced by reading §2.1–2.3 of
[`TIER-D-NONINTERFERENCE.md`](TIER-D-NONINTERFERENCE.md)). This paragraph first read: *"whether the
Tier-D argument survives the weakening, and what it degrades to, is the actual work."* **That
overstated it, and the overstatement is worth keeping visible because it was a claim about a
theorem made without re-reading the theorem.**

**Tier-D is not weakened at all.** Local respect is a **conditional** —
`¬(b ⇝ a) ⟹ obs(a)(dispatch(s,(b,α))) = obs(a)(s)` — and `⇝` **already includes consent (grant)**
as one of its five authorized channels, whose safety content is the grant seam's own invariants.
Introducing an authorized grant does not damage the theorem; it moves the pair out of the
antecedent-false branch and into a branch the theorem already covers.

**What changes is the deployment's claim, not the model's theorem.** The metal's `no_channel`
assertion stops holding for that pair, so the sentence this project can say about it changes from
*"no channel"* to *"exactly one channel, in one direction, and here is what governs it"*. That is
the honest description of the cost, and it is a smaller cost than the original wording implied.

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
| **Authorized monitor → policy observation** | ✅ **built (#193)** — and the naive direction is revocable, so ownership is inverted | `hv-metal/src/observe.rs` |
| **Bounded scheduling latency for the monitor** | ✅ **bounded (#194)**, ⚠ at the *simulation* tier only | `hv-sim`'s `policy_bounds_scheduling_latency` |
| **Actuator / sensor I/O reaching a guest** | ⚠ groundwork only; no real device is driven | `hv-metal/src/smmu.rs` |
| A non-Linux (small) monitor partition, **alone** | ✅ done on every default boot | `hv-metal/src/guest.rs`'s `load_guest` |
| **A non-Linux monitor partition running *beside* a Linux one** | ⚠ **never attempted — the two paths are mutually exclusive** | `hv-metal/src/main.rs` |
| Real silicon | ⛔ never run outside QEMU | [`QEMU-AND-METAL.md`](QEMU-AND-METAL.md) |
| SMP | ⛔ **not wanted** — see below | — |

⚠⚠ **FOUR of these rows were wrong within a day of being written, and the pattern is worth more
than the corrections.** Two went stale because the work got *done* (#193, #194) — the ordinary,
healthy kind. The other two were **wrong on arrival**:

* *"A non-Linux monitor partition — unknown, never attempted"* was **false when written**.
  `hv-metal/src/guest.rs`'s `load_guest` copies an in-image template into guest RAM, and the
  synthetic Arc 0–5 guests *are* bare-metal EL1 payloads. It runs on **every default boot**. The row
  was written from an assumption about what a "guest" meant here, not from the loader.
* The real gap was one question further in, and only appeared once the first answer was checked:
  the synthetic and `real-linux` paths are **mutually exclusive** (`main.rs`: *"the synthetic phases
  are replaced by the real-Linux capstone"*), so a small bare-metal monitor has never run **beside**
  a Linux partition — which is the configuration the whole mixed-criticality role needs.

★ **A requirements table is exactly as good as the reading behind each row**, and a row asserting
that something was never attempted is the cheapest of all to get wrong: nothing contradicts it,
because absence leaves no artifact to trip over.

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
