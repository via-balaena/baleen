<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Three green test tiers, one false property

*A scheduler property that a seeded simulation, a fuzz target and an exhaustive enumerator all
reported clean — and that was false the whole time. How it hid, what actually found it, and what the
proof added afterwards.*

---

Baleen is a static-partitioning separation kernel for AArch64/EL2 — a small hypervisor whose job is
to keep two guests apart. Its isolation core is machine-checked: **137 Kani harnesses** drive the
real `hv-core` code over symbolic inputs, **117 Verus obligations** carry the ∀-size half, and an
exhaustive enumerator sweeps every reachable state of small configurations. Two unmodified Alpine
Linux kernels boot on it and are refused by the hardware when they reach for each other's memory.

This is a story about a module *inside* that verified crate which none of it touched, and about how
the gap stayed invisible for four development arcs while three separate test tiers reported green.

The bug is not exotic. That is the point.

---

## 1. The property, stated four ways

`hv-core::sched` is the scheduling **mechanism**: it moves a vCPU onto a physical CPU and enforces
one invariant — a pCPU carries at most one vCPU. `hv-core::policy` is the layer that **picks**: which
runnable vCPU deserves the CPU next. The split is deliberate; the mechanism is proven, and the policy
sits above it and can only act through the mechanism's public transitions.

A policy has no safety invariant of its own, so it is held to *properties* instead. `policy.rs` named
four, and the first is **work conservation**:

> it never leaves a physical CPU idle while a vCPU is runnable.

Three artifacts asserted that property independently:

| tier | artifact | what it did |
|---|---|---|
| seeded simulation | `hv-sim`'s `run_policy` | churned vCPU availability across 256 steps × many seeds, checked the property after every scheduling fixpoint |
| fuzzing | `hv-fuzz/fuzz_targets/policy.rs` | the same property, driven by libFuzzer, in the weekly deep-verification job |
| exhaustive enumeration | `hv-sim::enumerate` | swept every reachable state of small configurations — including **every affinity mask** |

All three were green. The property was false.

---

## 2. The defect

`sched::System::run` refuses a dispatch that violates a vCPU's hard-affinity mask, returning
`NotAffine`. That guard is correct and has always been there.

`policy::next` chose *which* vCPU to run by ranking all runnable vCPUs by least-service-per-weight,
and *then* looked for an idle CPU — consulting no affinity mask at all. So it could recommend a
dispatch the mechanism was guaranteed to refuse. And `advance`, the driver that runs the policy to a
fixpoint, treated any refusal as a `break`:

```rust
if sys.run(dom, vcpu, pcpu, now).is_err() {
    break;                       // abandons the entire fixpoint
}
```

One vCPU pinned away from the lowest-numbered idle CPU is therefore enough to stop the machine. On a
one-domain, two-vCPU, two-pCPU system with `set_affinity(0, 0, 0b10)`:

```
total enacted over 200 ticks = 0
runtime(0,0) = Some(0)   runtime(0,1) = Some(0)
occupant0 = None         occupant1 = None
state(0,0) = Runnable    state(0,1) = Runnable
```

Both CPUs idle. Both vCPUs runnable. Zero transitions, and it never recovers.

Two details make it worse than a missed placement:

**It is self-reinforcing.** The unplaceable vCPU is the *most deserving* precisely because it never
runs — its accrued service stays zero while everyone else's grows. So the policy re-picks it, fails
again, and breaks again, forever.

**It starves the innocent.** vCPU `(0,1)` had a full affinity mask and was legally placeable on pCPU 0
the entire time. It never ran either, because the abandoned fixpoint never got that far.

And throughout, **no invariant was ever violated.** The mechanism's safety property — one vCPU per
pCPU — held perfectly. It is trivially satisfied by a machine that runs nothing.

---

## 3. Why nothing saw it

The three tiers were not three tiers.

`hv-sim`'s `run_policy` churned vCPU availability with a four-operation alphabet:

```rust
match rng.below(4) {          // abridged — arm bodies elided; the alphabet is the point
    0 => sys.admit(dom, vcpu),
    1 => sys.block(dom, vcpu, now),
    2 => sys.wake(dom, vcpu),
    _ => sys.offline(dom, vcpu, now),
}
```

`hv-fuzz`'s policy target used **the same four operations**, and asserted **the same property**. Two
files, two techniques, two names — and one alphabet. Neither ever called `set_affinity`. Every
affinity mask stayed at its default for the whole of every run, in both tiers.

The enumerator *does* sweep affinity — `for affinity in 0..(1u64 << cfg.pcpus)` — but it sweeps the
**mechanism's** hypercall surface, never the policy. And that turns out to be structural rather than
accidental: `policy` sits *above* the dispatch seam. A guest never asks to be scheduled; the
hypervisor's own timer tick invokes the policy. So no enumeration over the hypercall enum can reach
it, ever.

A later census made the shape exact: of **48 mutating operations in `hv-core`, 45 are reachable from
a hypercall** — swept exhaustively, with the variant count machine-checked against
`core::mem::variant_count`. The other three are `policy::advance`, `policy::set_weight` and
`policy::set_wake_boost`. The defect lived in the only part of the crate that the exhaustive argument
structurally could not reach, covered only by two generators that shared a blind spot.

The union looked like coverage. The intersection was empty exactly where the defect was.

---

## 4. The harness

### What actually found it, stated plainly

**Not the harness.** The order was: read the code while scoping an item in the honest ledger; notice
that `next` chooses a CPU without consulting affinity while `run` refuses on it; write an ordinary
`cargo test` that pins one vCPU away from the lowest idle CPU; watch it stall. **A plain unit test
reproduced this before any harness existed**, and a unit test could have caught it years earlier —
had anyone thought to set an affinity mask.

So the discovery was **conceptual**: asking *which axes do the generators actually move?* rather than
running a better tool. That is the transferable part, and pretending otherwise would sell a tool
where the lesson is a habit.

**What the proof added is precise and worth separating from discovery:**

| the unit test says | the harness says |
|---|---|
| here is *one* input where the policy stalls | there is *no* input where it stalls — over every admission pattern and every affinity mask, at this shape |
| on the code as I ran it | on the shipped code, symbolically executed |
| until someone deletes the test | in CI, where the fix cannot silently regress |

That is a real contribution and a different one. The rest of this section is about how the property
had to be *stated* to make it true — which is where the harness earned its keep.

### Written before the fix, and failing on purpose

The harness landed red against the unfixed policy, deliberately, so that the fix had something to
turn green:

```
** 1 of 1721 failed (8 unreachable)
Failed Checks: "work conservation: the policy reached its fixpoint while a legal dispatch remained"
Verification Time: 107.4534s
```

Exactly one check failed — the property itself. No unwinding assertion fired, and every memory-safety
and arithmetic check passed. After the fix: `0 of 1759 failed`, 148.7s.

The technique worth stealing is how the property is *stated*. The obvious phrasing —

> no idle pCPU coexists with a `Runnable` vCPU

— is **false of any scheduler**, and it is what the simulation and the fuzzer both asserted. A vCPU
whose affinity mask excludes every free CPU is runnable and legitimately unplaceable;
`set_affinity(_, _, 0)` is accepted, so a permanently unplaceable vCPU is representable. The naive
phrasing survived in those tiers only because nothing ever set a mask.

So the harness does not re-derive the placement rule at all. It asks the **mechanism**:

```rust
pol.advance(&mut sys, 0);

// After the fixpoint, no dispatch may still be legal.
for v in 0..VCPUS as u32 {
    for p in 0..PCPUS as u32 {
        assert!(
            sys.run(0, v, p, 0).is_err(),
            "work conservation: the policy reached its fixpoint while a legal dispatch \
             remained — the mechanism still accepts this vCPU onto this idle pCPU"
        );
    }
}
```

`run` is the production transition. It validates before mutating, so a refusal is a true no-op and
probing cannot perturb the state it probes. Three things follow:

1. **It is faithful by construction.** The oracle is the shipped guard, not a copy of it. There is no
   second derivation to drift.
2. **It needs no reimplementation** of the affinity bit-test in the test.
3. **It is automatically the *correct* statement.** An unplaceable vCPU can never make `run` succeed,
   so the qualification that the naive phrasing was missing falls out for free — rather than having
   to be known in advance and bolted on.

That third point is the one that generalises. Stating a property against the implementation's own
acceptance function gives you the edge cases you had not thought of yet.

Symbolic inputs: which vCPUs are admitted, and **every vCPU's affinity mask** — the axis the existing
tiers never moved.

---

## 5. The lesson

**Count the axes your generators move, not the tiers that assert.**

Three tiers asserting one property is worth very little if two of them draw from the same alphabet.
Redundancy across tiers buys nothing where the tiers share a blind spot, and a shared *op set* makes
that blindness nearly invisible — two files, two techniques, two names, all looking independent.

The check is cheap: diff the two generators' operation sets. If they match, you have one tier with
two names.

And the base rate is not reassuring. Once `set_affinity` was added to the simulation's alphabet, the
old policy failed on **seed 0** — the very first seed of the very first run. A blind axis is not a
rare corner you might eventually stumble into. It is a wall, and everything behind it is unexplored.

A second, smaller lesson from the same work: *"a bad policy is unfair, not unsafe"* stood in this
project's own module documentation as a reassurance. It is true, and it was beside the point. The
failure mode here was not unfairness — it was a total, permanent stall, with every safety invariant
holding throughout. **A safety invariant does not see liveness.** A layer that can only *choose* can
still choose nothing, forever.

---

## 6. What this does not claim

The harness proves work conservation at a **bounded shape** — one domain, two vCPUs, two pCPUs, a
concrete quantum, and a single instant. That is ∀-values on the symbolic axes, not ∀-size.

`policy.rs`'s other three properties remain at the simulation tier, and **two of them are not
reachable by any larger Kani harness**:

- **Weighted-proportional fairness** is a statement about a *limit*.
- **Starvation-freedom** — the bound `(W_total − wᵢ) × quantum / pcpus + 1` — is a statement about
  *unbounded runs*.

Neither is a bounded-depth property, so closing them needs a different technique, not a bigger
harness. That matters here specifically: the starvation bound is what a safety monitor running as a
partition would budget its latency against, and it is still the weakest tier in the project.

`advance`'s `break` is now unreachable — every refusal reason is excluded before it — but that is
**by construction, not by proof**. Nothing yet asserts "`next` never proposes a decision the
mechanism refuses."

---

## Reproduce it

```sh
cargo kani -p hv-verify --harness advance_leaves_no_legal_dispatch_unmade   # ~150 s
cargo test -p hv-core policy                                               # the regression tests
cargo run -p xtask -- seam-census        # the 48/45/3 census described in §3
```

The fix, the harness and the census are in
[`hv-core/src/policy.rs`](../hv-core/src/policy.rs),
[`hv-verify/src/lib.rs`](../hv-verify/src/lib.rs) and
[`xtask/src/main.rs`](../xtask/src/main.rs). Each carries its reasoning inline, including the kill
probes: reverting the fix fails exactly the tests that name the thing removed, and no others.
