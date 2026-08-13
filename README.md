<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Baleen

[![CI](https://github.com/via-balaena/baleen/actions/workflows/ci.yml/badge.svg)](https://github.com/via-balaena/baleen/actions/workflows/ci.yml)
[![Deep verification](https://github.com/via-balaena/baleen/actions/workflows/deep-verify.yml/badge.svg)](https://github.com/via-balaena/baleen/actions/workflows/deep-verify.yml)

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

> **Where to go next.** This file is long, deliberately — it carries the claims *and* the honest
> ledger of what is not proven. Three shorter ways in, by what you actually want:
>
> | if you want | go to |
> |---|---|
> | the picture — what is proven, what is only witnessed, what is open | **[the assurance map](https://via-balaena.github.io/baleen/)**, whose every figure is generated from the gates |
> | one defect, end to end, with no prior context | **[Three green test tiers, one false property](docs/CASE-STUDY-WORK-CONSERVATION.md)** — a scheduler property that a simulation, a fuzz target *and* an exhaustive enumerator all reported green while it was false |
> | the design documents | **[`docs/README.md`](docs/README.md)** — a map of all of them, with three reading orders |

## What this is, honestly

**A small type-1 hypervisor whose isolation core is machine-checked, and a discipline for
evidencing the part that cannot be.**

Conceptually it is **Xen-shaped**, not seL4-shaped: `hv-core`'s vocabulary is domains, grant
tables, event channels, a p2m and a scheduler. seL4 is a different category of object — a
microkernel you build a VMM *on top of* — and its proof is a different kind of claim.

### Three tiers of evidence, kept apart on purpose

Most of the value here is in **not** letting these blur into one word.

| tier | what it covers | how |
| --- | --- | --- |
| **Proven** | the model's isolation invariants; the emitter refining the authorized leaf map | **137 Kani** harnesses (∀-values at bounded size) + **117 Verus** obligations (∀-N); ∀-address refinement over `hv-s2` |
| **Demonstrated** | the metal | boot witnesses: two unmodified Alpine kernels, four vCPUs, one pCPU, **zero** Stage-2 device pass-through, each guest hardware-refused from its peer's RAM |
| **Argued** | Tier-D non-interference's instantiation to concrete Baleen | prose composition over proved generic lemmas — declared, not hidden |

### What is actually distinctive

- **The proven model is wired in as a live oracle.** The metal does not reimplement the model's
  decisions — it *asks* it. Domain lifecycle, `p2m` operations and every scheduler transition
  are dispatched into `hv-core` at runtime through a single funnel, and **a refusal halts the
  machine**. On those transitions the metal cannot silently drift from what was proved; it dies
  loudly instead. (Scope, precisely: this binds the metal to the model *where it dispatches*.
  It is not a proof that the implementation refines the model — that is what seL4-style
  functional-correctness work does and this does not.)
- **A witness/probe discipline for the unprovable layer.** Every mechanism carries a required
  boot marker, a forbidden twin, and a **kill probe that is actually run** — and probes that
  *fail* to kill are recorded as findings rather than quietly dropped. Several designs here exist
  because a probe refuted its own prediction.
- **An honest ledger.** `docs/` and the commit log keep refuted hypotheses, undercounts and
  wrong diagnoses in place, because the reasoning is the reusable part.

### What it is not

- **Not seL4-tier.** seL4 proves full functional correctness, at a proof-to-code ratio widely
  reported around 20:1. Here it is **0.53:1** — 6 635 non-comment lines of Kani + Verus against
  the 12 406 of `hv-core` + `hv-s2` + `hv-vdev` + `hv-part` — property-directed verification rather than
  functional correctness. A deliberately different bargain: a weaker guarantee, far more
  cheaply, with the remainder enforced at runtime instead. If you need seL4's guarantee, the
  gap *is* the point. (Both sides of that ratio are non-comment lines; comparing
  comments-included proof against comments-excluded code would flatter it to ~0.8:1, which is
  the sort of thing this repo's ledger exists to catch.) ⚠ **The ratio is GATED**
  (`cargo xtask doc-counts`) to two decimal places; the two component counts beside it are not,
  because they move on every PR while the ratio does not — it was unchanged after +178 lines of
  proof and +150 of code. A regression that matters — proof stalling while the model grows — moves
  the second decimal long before anyone would notice by eye.
- **Not feature-comparable to Xen.** No toolstack, no migration, no PV drivers, one board.
- **Not production.** Single-CPU, one board, QEMU-only; `hv-metal` is the bare-metal half and is **not**
  a Kani target, and every rung's docs say so where it matters.

The open question this is really poking at: **how much assurance can you get for a small
fraction of a full-verification budget, and exactly which parts do you lose?** The honest ledger
is what makes that answerable instead of rhetorical.

## The architecture in one picture

Everything above the fence is proof-reachable; everything below it is not. That single line
explains most of the honest ledger.

```
  guest A — unmodified Linux            guest B — Linux, or a bare-metal payload
             │                                        │
             │        traps · hypercalls · MMIO       │
  ═══════════╪════════════════════════════════════════╪═══════════════  EL2
             ▼                                        ▼
  ┌────────────────────────────────────────────────────────────────┐
  │ hv-vdev   the devices a guest sees — GICv3, PL011, SGI decode  │
  ├────────────────────────────────────────────────────────────────┤
  │ hv-core   domains · grants · event channels · p2m · scheduler  │   every crate
  │           · policy                              — the model    │   in this box
  ├──────────────────────────────┬─────────────────────────────────┤   is #![forbid(
  │ hv-part  partition arithmetic│ hv-s2  Stage-2 emitter, and the │   unsafe_code)]
  │          windows, frame runs │        ∀-address refinement     │   and reachable
  ├──────────────────────────────┴─────────────────────────────────┤   by Kani, Verus
  │ hv-hal    the southbound fence — architecture-neutral traits   │   and the sweeps
  └────────────────────────────────────────────────────────────────┘
  ═══════════════════════  the proof fence  ══════════════════════════
  ┌───────────────────────────┐        ┌───────────────────────────┐
  │ hv-sim    host backend    │        │ hv-metal   AArch64 / EL2  │
  │ fake memory, manual clock │        │ boot · MMU · Stage-2 ·    │
  │ deterministic simulation  │        │ vGIC — the unsafe layer   │
  └───────────────────────────┘        └───────────────────────────┘
     runs on a laptop, cargo test          QEMU today; not yet silicon
```

**The southbound fence is the same line as the `unsafe` boundary, and the same line as the proof
boundary.** Above it, seven crates are `#![forbid(unsafe_code)]` — enforced by the compiler, not by
convention — and every verification tool in the project can reach them. Below it, `hv-metal` needs
`unsafe` for MMIO and assembly, is excluded from the workspace, and is held to boot witnesses
instead.

⚠ **That is not a small remainder.** Shipped code splits almost exactly in half either side of the
fence — the live figure is on the [assurance map](https://via-balaena.github.io/baleen/), which
generates it rather than restating it. Anyone reading "machine-checked isolation core" should know
what fraction that phrase covers.

⚠ **The picture above replaced one that had gone stale**: it drew a Xen personality that was
dropped, labelled boxes with milestone numbers that had moved on, and omitted `hv-part`, `hv-vdev`
and `hv-s2` entirely — three of the five crates inside the fence. A diagram is prose with lines
around it and rots exactly as fast.

⚠ That sentence used to read *"~85% of bugs live in `hv-core`"*. **Nobody measured 85%.** It was a
design intuition wearing a statistic's clothes, and this repo gates the numbers it states — so the
number is deleted rather than sourced, per design-lesson #276.

## Workspace

The comment ratio across this workspace is high on purpose: much of the project's argument
lives in doc comments, which is why `cargo xtask metal-lint` builds `hv-metal`'s rustdoc and
`clippy::missing_docs_in_private_items` is enabled on `hv-hal`, `hv-s2` and `xtask` — the
argument has to be as maintained as the code it explains.

> ⚠ **This table used to carry a `lines` column and it has been deleted, not corrected.** Every
> entry had drifted — `hv-metal` was stated at 10 946 against a real 24 974, `fvp-probe` at 214
> against 2 556 — so a reader got a **2×–12× wrong** impression of the project's scale from the one
> place they would look first. Nothing could check it, and a gate on line counts would fire on every
> PR that adds code: a gate with no signal, which trains people to bump a number to make CI green.
> Per design-lesson #230, **a claim in prose that nothing checks is deleted rather than corrected.**
> What the table is *for* is what each crate does; `tokei`/`wc -l` will tell you the size, freshly.

| crate       | what it is |
| ----------- | ----------- |
| [`hv-hal`](hv-hal/README.md)    | the *southbound* fence: hardware traits (`GuestMemory`, `TimeSource`, `VcpuOps`) |
| [`hv-core`](hv-core/README.md)   | the model: domains, grants, event channels, p2m, scheduler. `no_std`, **zero external crates** (one path dep on `hv-hal`), and zero `unsafe` — `#![forbid(unsafe_code)]`-enforced |
| [`hv-s2`](hv-s2/README.md)     | the Stage-2 page-table **emitter**, and the ∀-address refinement theorems over it |
| [`hv-vdev`](hv-vdev/README.md)   | guest-facing **device models** under the proof fence — GICv3, PL011, SGI decode, pending sets |
| [`hv-part`](hv-part/README.md)   | how the machine is **partitioned among guest slots** — windows, frame runs, domain ids — as `const fn` arithmetic proven ∀-partition rather than `const assert!`-ed at the two slots this board deploys |
| [`hv-sim`](hv-sim/README.md)    | host harness — fake memory, hand-cranked clock, seeded deterministic simulation + ∀-size sweeps |
| [`hv-verify`](hv-verify/README.md) | the **Kani harnesses** (137) and, under `verus/`, the ∀-N **Verus** proofs (117 obligations) |
| [`hv-metal`](hv-metal/README.md)  | the bare-metal AArch64/EL2 binary: boot, its own stage-1 MMU, Stage-2, vGIC, the real-Linux path |
| [`hv-fuzz`](hv-fuzz/README.md)   | `cargo-fuzz` targets against the hypercall dispatcher |
| [`fvp-probe`](fvp-probe/README.md) | ⚠ **not part of the hypervisor** — a standalone bare-metal instrument for Arm's AEM FVP, measuring SMMU translation caching and invalidation (honest-ledger 2(d)), which QEMU structurally cannot show. Workspace-excluded; its **verdicts** are deliberately ungated, its **health** is (`cargo xtask fvp-lint`) |
| [`board-probe`](board-probe/README.md) | ⚠ **not part of the hypervisor** — measures the platform facts `hv-metal` assumes from QEMU `virt` (exception level, `SCTLR_EL2` at reset, cache line, `ICH_VTR_EL2`, granule/PA/VMID), so a future port is scoped from numbers rather than guesses. Self-tests on QEMU; see its README |
| [`xtask`](xtask/README.md)     | build/test automation and the gate corpora (`cargo xtask <task>`) |

**Four** crates are **excluded from the workspace** — not "until their milestones", but
permanently. `hv-metal`, `fvp-probe` and `board-probe` build for
`aarch64-unknown-none-softfloat` and cannot link for the host; `hv-fuzz` needs
nightly/libFuzzer at build time. All four are built and gated out-of-band
(`cargo xtask qemu-test`, `qemu-linux-test`, `metal-lint`, `fvp-lint`, and the
`fuzz targets build` job).

⚠ **The exclusion has a cost worth knowing: an excluded crate loses *every* `--workspace`
gate, not just the one it was excluded for.** `hv-metal`'s rustdoc was built by nothing at
all until that was noticed; `fvp-probe` was built by nothing at all for four milestones
after that, which is the same finding one crate along. `board-probe` was therefore added to
`cargo xtask fvp-lint` **in the commit that created it**.

> ⚠ This paragraph said "`hv-metal` and `hv-fuzz`" while there were four. An inventory that
> undercounts its own subject makes the ones it omits invisible — and the omitted two are
> precisely the crates whose exclusion cost had already bitten twice.

## Direction

The long-run build target is a greenfield **"slim Qubes"** — GPU-accelerated near-metal
disposables, an offline vault, direct device attach and a trusted input/GUI domain, on the proven
core, using **hardware-virt + virtio** so unmodified guests need no knowledge of Baleen. The
once-planned Xen personality (`baleen-xenabi`) stays **dropped**: matching Xen's ABI would drag its
unproven semantics onto a clean core and leave us chasing an external surface forever. See
[**`docs/ROADMAP.md`**](docs/ROADMAP.md).

Where the work actually is has moved. The model is proven and the effort is now on the **seam
between the proof and the metal**. Two unmodified Alpine kernels run
isolated on hardware EL2, and the device path — a DMA-capable device under the same proven `p2m` the
CPU uses — **is closed**: the SMMU rungs took it from a default-deny stream table to the metal
deriving that table, and `docs/SMMU-DEVICE-PATH-COMPOSITION.md` states the whole path as one theorem.

⚠ **This paragraph said "the current arc is putting a DMA-capable device under the same proven
`p2m`" after that arc had closed.** A "current arc" sentence is a status claim wearing a design
claim's clothes, and it is the single most rot-prone sentence shape in a README — which is why the
milestone log moved out and why what remains here is written as *what is true*, not *what is next*.

### Identity vs. personality

`hv-core` does not know what Xen is. Schedulers, event-channel state machines, memory accounting
and grant-style resource lifecycles are *generic* hypervisor logic. Guest-facing wire formats and
boot protocols live in a **personality** northbound of the core, in the same architectural
position `hv-hal` sits southbound — the core stays ABI-agnostic, and the personality is chosen per
target.

The clean-room / ABI-as-spec discipline ([`CLEANROOM.md`](CLEANROOM.md)) governs any *standard*
wire format implemented here (virtio) — it never governed a Xen-compatibility layer, because there
is not going to be one.

⚠ **This section used to restate the dropped-Xen decision and the slim-Qubes goal in full, one
screen after the paragraph above had already made both points.** Two passages saying the same
thing drift apart rather than reinforce; the duplicate is deleted, not reworded.

### ARM and x86 are co-equal targets

Just as the *personality* keeps the core ABI-agnostic northbound, the `hv-hal` fence keeps
it **architecture-agnostic southbound**. `hv-core` names no CPU architecture: its page
tables are a generic 4-level hierarchy (what AArch64 *and* x86-64 both use), and it reaches
hardware only through arch-neutral traits. The **first `hv-metal` backend is AArch64** (the
ARM virtualization extensions at EL2, Stage-2 translation, the GIC) — chosen to lead because
the development machine is Apple Silicon, so an EL2 backend runs *same-architecture* under
QEMU with no cross-emulation; the M3–M5 entries in
[`docs/MILESTONES.md`](docs/MILESTONES.md) are described in those terms. An
**x86-64** backend (Intel VMX / EPT, the LAPIC) is an **equally first-class goal**, not an
afterthought: it is a second implementation of the same `hv-hal` traits, and the diamonded
brain above it does not change. This is a load-bearing design constraint — the fence's trait
surface stays free of any architecture-specific concept, so each port is a new metal layer,
never a rewrite.

## Try it

Nothing here needs hardware, a VM image, or a nightly toolchain.

```sh
cargo test --workspace       # the model, the seeded scenarios, the property tests
cargo xtask ci               # what CI runs: fmt · clippy · test · doc · every doc gate
```

Then the metal, still on your laptop — QEMU is the only extra requirement:

```sh
cargo xtask qemu-test        # hv-metal boots at EL2 and asserts its boot markers
hv-metal/linux/fetch-guest-image.sh   # builds a checksum-pinned Alpine (~30 s, once)
cargo xtask qemu-linux-test  # two unmodified Alpine kernels, isolated, under EL2
```

And the proofs, which are slower and need their own toolchains:

```sh
cargo xtask kani-harnesses   # what the Kani corpus contains, by name
cargo xtask verus-counts     # the Verus obligations, by count
cargo kani -p hv-verify --harness <name>      # run one (a full run takes minutes)
```

And the two censuses that police the *coverage argument itself* — cheap enough to run on every PR,
and both included in `cargo xtask ci`:

```sh
cargo xtask seam-census      # every hv-core transition is hypercall-reachable, or DECLARED above the seam
cargo xtask hvcall-census    # the fuzz target driving HvCall constructs every variant
```

⚠ **`seam-census` exists because the exhaustive sweep reaches `hv-core` through exactly one door.**
`HVCALL_VARIANT_COUNT` is machine-checked against `core::mem::variant_count::<HvCall>()`, so
anything a *hypercall* can reach is swept — and a handful of operations sit **above** that seam,
driven by the hypervisor's own tick rather than by a guest, where no enumeration can ever reach
them. Those are covered by named generators instead, and the census fails if one loses its
generator, if the classification goes stale, or if a new operation appears unclassified.

The live split, and which subsystems it leaves uncovered, is on the
[assurance map](https://via-balaena.github.io/baleen/) — generated, so it stays true.

And the map's own data:

```sh
cargo xtask site-data        # regenerate it from the gates; `ci` fails if it is stale
```

★ **`cargo xtask ci` is the honest answer to "is any of this real?"** — it is the same entry point
CI uses, and it fails on a stale number in this file as readily as on a broken test.

## The evidence, in detail

*What the commands above actually establish, and where each stops.*

### Seeded simulation — cheap, deterministic, and the weakest tier

M1's headline test runs `hv-core` through 10,000 seeded interleavings of the toy credit-account
state machine, checking its conservation invariant on every transition. Same seed → same run,
exactly — so any future invariant break is a one-line regression test, not a Heisenbug.

⚠ It is also the tier that has actually been wrong. See the
[case study](docs/CASE-STUDY-WORK-CONSERVATION.md): a property this tier reported green for four
development arcs was false the whole time.

### Exhaustive enumeration — a proof, not a sample, at small size

`hv-sim::enumerate` does **bounded model checking**: for a tiny configuration it breadth-first
visits *every* reachable state and checks the integrated invariant at each. CI runs shallow
per-seam sweeps in seconds; the **23** deep exhaustive sweeps (`cargo test --release -- --ignored`)
have cleared **millions** of distinct states with zero violations:

| sweep | depth | states |
| --- | --- | --- |
| grant↔page-type + page-table↔grant — including cross-domain foreign *node* shares, not just leaves | 7 | ≈ 828k |
| the whole integrated core | 5 | ≈ 415k |
| event↔scheduler | 7 | ≈ 2.1M |

### Bounded → unbounded: how small sweeps say something about all sizes

Those sweeps are bounded two ways — hypercall **depth** and config **size** — and each is closed
by a separate argument.

**Depth, by saturation.** The enumerator distinguishes a run that merely exhausts its budget from
one that **saturates**: the BFS frontier goes *empty*, meaning the config's whole reachable set has
been visited at **every** depth. That is an all-depths theorem, not a bound. Most configs saturate,
because nothing in them grows a refcount without limit:

| config | states at saturation |
| --- | --- |
| domain lifecycle | 47k |
| vCPU affinity | 237k |
| the delegation forest | 58k |
| the full four-level page-table hierarchy | 1,030,856 orbit representatives |

⚠ **One config genuinely does not saturate, and it is the interesting one.** Grant↔p2m *together*
is infinite: a frame can be mapped an unbounded number of times, so the space is finite only per
depth. **That is precisely where enumeration stops being able to help and deductive proof becomes
unavoidable** — you cannot enumerate an infinite space — and it is why Tier C exists.

**Size, by cutoff and symmetry.** A per-invariant **locality** analysis shows each of the 28
invariants is violated by a bounded witness, so a size cutoff of 4 domains / 3 frames bounds the
search — already covered as a base case by the 3-domain grant/p2m and 4-domain delegation sweeps. A
**data-independence** argument completes it: the core branches on no literal id except dom0-at-boot
and vCPU-0-at-notify.

★ **That symmetry argument then paid for itself twice.** Canonicalizing each state to its orbit
representative before dedup — over frame, port and grant id-permutations — collapses each orbit to
one state, up to ≈20× fewer for frame-heavy configs. It is what turned the full page-table
hierarchy from *argued* finite into a **measured** all-depths theorem. ⚠ Its soundness is checked
ruthlessly, because a wrong canonicalization would silently hide states rather than fail: the group
is verified to be a genuine automorphism on saturated reachable sets, and the reduced run verified
to hide no reachable orbit.

The full argument, its two residuals handed to Tier C, and the measured saturation table are in
[`docs/TIER-B-CUTOFF.md`](docs/TIER-B-CUTOFF.md).

### Deductive proof — the ∀-size jump

Bounded model checking, however exhaustive, enumerates *small* states. This tier proves every
transition preserves every invariant at **arbitrary size**, reasoning over all states at once. The
tooling is a bridge, and the two halves do different jobs:

- **[Kani](https://github.com/model-checking/kani)** symbolically executes the **real** `hv-core`
  code — a scalar made symbolic is checked across all 2³² values by its SMT backend, with no bound.
  It runs on shipped code, which is what makes it evidence rather than modelling.
- **Verus** carries the arbitrary-*size* proofs, over a mirror written in its dialect. That mirror
  is the price of the ∀-size step, and the fidelity argument for it is stated rather than assumed.

The first spike discharged the cleanest Tier B residual — the grant refcount infinity — as a
machine-checked theorem: `WritableExceedsMaps` (`writable_maps ≤ maps`) is preserved by the map and
unmap count-transitions for **every** refcount magnitude, and the unchecked increment provably
cannot overflow. The proofs call the *same* count arithmetic production does, so there is one
derivation and nothing to drift.

★ **The spike earned its keep by refuting an assumption rather than confirming one.**
`WritableExceedsMaps` is **not** self-inductive under unmap — its preservation *borrows* from
`RefcountMismatch`, making the "±1 lockstep" a genuine coupling rather than a convenience. That
finding is what set the next obligation's shape.

⚠ **This section used to end "the proofs run in the scheduled `Deep verification` workflow, not the
per-PR gate", and that had been false for some time.** `kani proofs (PR)` and `verus proofs (PR)`
are **required checks on `main`**, run on any PR touching `hv-hal` / `hv-core` / `hv-part` /
`hv-s2` / `hv-vdev` / `hv-verify`; a PR touching none of them green-skips in seconds. `Deep
verification` remains for what does not belong in a PR gate — the ∀-size sweeps, fuzzing, and a
weekly backstop re-run of the proofs.

The decision, the repo and CI shape, and that finding are in
[`docs/TIER-C-SPIKE.md`](docs/TIER-C-SPIKE.md).

## Milestones

The full append-only log — 23 entries from M1's toy hypercall to two Alpine kernels on EL2, each
saying what was built, why that next, and what it cost — is **[`docs/MILESTONES.md`](docs/MILESTONES.md)**.

It lived here until it was 561 of this file's 850 lines. It is a *log*, not status: for where the
project actually is, *What this is, honestly* above is the answer.

## License

Dual-licensed under either of [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at
your option.
