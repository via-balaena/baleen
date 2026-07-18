<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Tier D — non-interference (the property definition + the bridge spike)

*Status: **property definition decided and validated on real code; tooling/bridge call made;
spike green on both axes.** This is the deepest and last tier of the true-diamond program — the
"are we checking the **right** things" capstone. Tiers A–C prove the invariants hold in every
reachable state, ∀-N; Tier D asks whether those invariants **collectively imply real isolation**.
Read alongside `hv-sim/src/noninterference.rs` (the enumerator bridge), `hv-verify/verus/
unwinding_signal.rs` (the Verus unwinding spike), and `docs/TIER-C-SPIKE.md` (the tier before).*

## 0. What Tier D is, and why it is different

Through Tier C, every proof answers **"is each invariant maintained?"** — preservation,
`∀ s. INV(s) ⇒ INV(t(s))`. That is *checking things correctly*. Tier D answers a different
question: **do the 28 invariants, together, mean what we want — that a domain is isolated?** A
model can maintain a rich invariant set flawlessly and still be checking the *wrong* things
(nothing so far says the invariant set is *sufficient* for isolation). Tier D closes that gap by
stating an isolation property *independent* of the invariants and proving the invariants imply
it. The standard vehicle (seL4-infoflow, CertiKOS) is **non-interference** via **unwinding**.

This is qualitatively harder than per-invariant preservation: it quantifies over the *whole
observation* and over *pairs* of executions, and the definition itself is the hard part — a wrong
definition proves nothing. So the tier is structured **definition → bridge → spike → (scale)**,
mirroring Tier C's Kani-bridge-then-Verus discipline.

## 1. The transition system

A **state** is the whole `Hypervisor` (`hv-core/src/hypervisor.rs`). A **transition** is
`dispatch(caller, α)` for a hypercall `α ∈ HvCall`. The one fact that makes non-interference
*expressible* here: **every call carries an explicit `caller: DomId`** — the acting principal is
unambiguous, so "who performed this step" is a first-class part of the transition, not something
we must infer. Domains are the security principals.

## 2. Design call #1 — the property definition (the ballgame)

### 2.1 `obs(a)` — domain `a`'s observable isolation surface

`obs(a)` is the projection of the whole state onto the entities that **belong to `a`** — a
*filter* of `enumerate::Snapshot` (the read-once projection symmetry reduction already built) down
to one domain. Concretely (`noninterference::obs`):

| component | fields |
|---|---|
| liveness / credit | `life[a]`, `balance(a)` |
| event-channel ports (`dom == a`) | state, pending, masked |
| grant rows (`grantor == a`) | grantee, frame, readonly, **maps, writable_maps** |
| held mappings (`grantee == a`) | {(grantor, gref, writable)} |
| vCPUs (`dom == a`) | run-state (incl. its pcpu), affinity mask |
| owned frames (`owner == a`) | refs, writable_refs, pagetable_refs, type, pinned |
| page-table edges (`owner(parent) == a`) | (parent, slot, child, writable, leaf) |

`s ~_a s'` (observational equivalence) is defined as `obs(a)` equality, so output-consistency is
immediate; the content is in **local respect** (§2.3).

**Two deliberate exclusions — each a real granularity call** (too fine and legitimate flows look
like violations; the user's exact warning):

- **The global pCPU-occupancy vector is out.** `a` observes its *own* vCPUs' `Running{pcpu}` (the
  pcpu `a` itself chose — `SchedRun` takes the pcpu as a caller input), but **not** who else
  occupies pcpus. Including it would make every `SchedRun` by anyone read as interference — but
  pcpu contention is a *timing/availability covert channel* the model deliberately abstracts
  (`runtime`/`dispatched_at` are already dropped from `state_key`; same fence as superpage
  contiguity, design-lesson #14e). Excluding it is what keeps the property both non-vacuous and
  *true*. This is the honest **model-fidelity boundary**: Tier D proves *storage-channel* /
  *explicit-flow* non-interference for the model; scheduling timing channels are out of scope, an
  M-level (real-hardware) concern.
- **Authority is out** (`may_create[a]`, the `controls` matrix — outgoing and incoming). Authority
  is `a`'s *power over others*, not others' ability to corrupt or read `a`. When `b` delegates a
  capability *to* `a`, that changes `a`'s authority but touches **none** of `a`'s resources — and
  its correctness is already governed by the Tier-C control-forest invariants
  (`ControlEdgeOrphaned` etc.). Keeping authority in `obs(a)` would flag every legitimate
  delegation as interference. So authority delegation is governed by Tier C; `obs(a)` is `a`'s
  *resource* surface.

### 2.2 `b ⇝ a` — the authorized-channel relation

State-dependent and **intransitive** — which is *correct* for a capability system (least
privilege, no implicit transitivity, design-lesson #11). A step by `b` may legitimately move
`obs(a)` iff a **direct** relationship holds, and **each is exactly the safety content of one
seam**:

| channel | condition (in state `s`) | what it authorizes `b` to move in `obs(a)` |
|---|---|---|
| self | `b == a` | anything of `a`'s |
| **consent** (grant) | `a` has an active grant with grantee `b` | `a`'s frame refs; `a`'s grant map-counts (`b` maps/unmaps/copies) |
| **signal** (evtchn) | `a` holds a port `Interdomain{b}` or `Unbound{b}` | `a`'s port state / pending (`b` sends/closes/binds) |
| **authority** (control) | `controls[b][a]` | `a`'s vCPU affinity; `a`'s whole state (`b` destroys `a`) |
| **creation** | `may_create[b] ∧ ¬live[a]` | `a` `Dead → Live` |

**The thesis — why this shows we check the *right* things.** `⇝` is *exactly the union of the
relationships the three seams guard.* Each seam invariant is the safety content of one channel,
and non-interference is: **absent every channel, `s ~_a dispatch(s,(b,α))`.** That is the
frame-lemma's *"disjoint ⇒ no perturbation"* (`frame_lemma.rs`) lifted from one read-value to the
whole of `obs(a)`, over every transition. And the invariants keep `⇝` **honest**: the grant
*no-end-while-mapped* rule (`grant.rs`, `InUse`) guarantees that while `b` can affect `a` through a
mapping, `a`'s grant to `b` *stays active* — so the channel the relation names is provably still
present. Reciprocity does the same for the signal channel (see §5). The invariants are not
arbitrary: each is the guard on exactly one authorized channel, and there are no others.

### 2.3 Local respect — the core lemma

> **Local respect.** For all reachable `s`, all principals `b`, all calls `α`, and all `a ≠ b`:
> `¬(b ⇝ a) ⟹ obs(a)(dispatch(s,(b,α))) = obs(a)(s)`.

This is the unwinding condition that carries non-interference (with output-consistency, immediate
from `~_a` = `obs(a)`-equality). It generalizes `frame_lemma.rs`'s mini-unwinding (a summation is
witness-local) from one invariant's read-value to all of `obs(a)`, across every transition.

### 2.4 The one honest wrinkle — the intransitive `DomainDestroy` term

`DomainDestroy(c)` is the **sole multi-domain transition**: `close_all`/`clear_unbound_into`/
`revoke_grants_to` reach `c`'s *partners*. So if `a` holds an outbound reference **naming `c`** (a
grant `a` offered `c`; a port `a` opened toward `c`) and `b` controls `c`, then `b` destroying `c`
moves `obs(a)` through a **two-hop** flow (`b ⇝ c`, `a ↔ c`) — the classic **intransitive
non-interference** structure. Every *other* transition is one-hop. The relation therefore carries
one extra term (`noninterference::Channels::teardown_reach`):

> `∃ c: controls[b][c] ∧ (a granted to c ∨ a holds a port toward c)`.

We did not guess this — **the bridge found it** (§4). Every resource-corrupting reach of
`DomainDestroy(c)` is *blocked* when it would strand `a`: a live grant map of `c`'s frames by `a`
makes destroy refuse (`DomainBusy`); the only reachable effect on `obs(a)` is the cleanup of `a`'s
*own* outbound references to `c`, which is exactly what this term authorizes.

## 3. Design call #2 — tooling and the bridge

**Continue in Verus** (not Lean/Coq). The Tier-C mirror discipline worked three times; Tier D's
local respect is still one-step preservation over the *same* state, needing no semantics Verus
cannot express. Lean/Coq's extra model-fidelity gap buys nothing here.

**Bridge first — validate the definition on real code before the ∀-N proof.** Exactly the Kani→
Verus move that opened Tier C (design-lesson #20): a wrong `obs`/`⇝` should yield a *counterexample*,
not a false proof. So the enumerator is extended (`hv-sim/src/noninterference.rs`) to check local
respect on the **real** `Hypervisor`: for every reachable small state × every transition `(b,α)` ×
every observer `a ≠ b`, assert `¬(b ⇝ a) ⟹ obs(a)` unchanged. This validates the property
definition comprehensively and cheaply *before* the hard Verus unwinding proof.

## 4. The bridge — results (green, on real code)

`noninterference::check(cfg, Channels::full())` sweeps the whole `states × transitions × observers`
product on the real integrated core. Measured (`cargo run --release --example ni_probe`):

| config | reachable states | checks | **unauthorized** checks | violation |
|---|---|---|---|---|
| 2-domain, depth 3 (**CI test**) | 3,342 | 788,712 | **307,744** | none |
| 2-domain, depth 6 (deep) | 200,000 (capped) | 47,200,000 | 14,842,394 | none |
| 3-domain, depth 6 (deep) | 102,641 | 25,249,686 | 10,307,974 | none |

Local respect **holds** under the full relation, and **non-vacuously**: even the CI-sized run
exercises 307,744 *unauthorized* (state, transition, observer) triples — cases where `b` has **no**
channel to `a`, so any change *would* be a violation, yet `obs(a)` is preserved. The property
definition is validated on the real code.

**The bridge has teeth (non-vacuity).** Dropping any one channel term makes the check *find* the
flow that term governs — the Tier-C "remove the fix → counterexample" discipline, applied to a
channel term (`noninterference::tests`):

| term dropped | flow surfaced |
|---|---|
| grant | a peer mapping a grant `a` offered moves `a`'s frame refs / grant map-counts |
| evtchn | a peer sending/binding on a channel `a` is party to moves `a`'s port state |
| control | a controller destroying / setting affinity on `a` moves `a`'s observation |
| **teardown-reach** | **the intransitive `DomainDestroy` two-hop** — a domain destroying a peer it controls clears a *third* domain's outbound reference to that peer (needs 3 domains) |

The teardown-reach row is the intransitive finding of §2.4, surfaced empirically: it is caught in
the three-domain config and would be invisible in two domains (no third observer). The bridge is
what *made the definition honest*.

## 5. The Verus spike — signal-channel local respect, ∀-N (green)

To measure the **deductive** cost (the axis where the "person-months, research-grade" caveat might
finally bite), one unwinding lemma is proven end-to-end in Verus on a **second seam** — the signal
channel (`frame_lemma.rs` already covers the memory channel). `hv-verify/verus/unwinding_signal.rs`
(2 verified, 0 errors) proves, over an **arbitrary port population**:

> under event-channel **reciprocity** (the interdomain peer map is an *involution*), if `a` holds
> no port toward `b`, then `b` holds no port toward `a` — so a `send` by `b` cannot set any pending
> bit of `a`, and `obs(a)`'s signal projection is preserved by a step from a `b` with no signal
> channel to `a`.

The non-trivial content is the **two-sides bridge**: the channel relation is stated on `a`'s ports
(`a_port_toward`), the `send` transition acts from `b`'s ports, and **reciprocity** is what aligns
them — the same *"one property borrows from a relational invariant"* shape as design-lessons
#20/#21, now on the evtchn seam. Non-vacuity validated: dropping the involution (reciprocity)
hypothesis makes Verus reject the proof.

**Effort finding.** ~2 lemmas, 2 scratch iterations (one trigger fix). *Lower* than any Tier-C
obligation. Combined with `frame_lemma.rs` (the memory channel, ~5 lemmas), the honest read is:
**per-channel local respect is tractable** — the same textbook borrows-from-a-relational-invariant
shape recurs, and Verus/Z3 handle the ∀-N quantifiers cleanly. The person-months caveat did **not**
bite for these two channels.

## 5a. The control/affinity channel, ∀-N (green) — and a channel that *doesn't* borrow

The next incremental arc (chosen over committing to the whole remaining program): the third
direct channel, **authority/control**. `hv-verify/verus/unwinding_control.rs` (3 verified, 0
errors, **first try**) proves, over an **arbitrary vCPU population**, that a scheduler step by a
`b` with no authority over `a` (and `b ≠ a`) leaves `a`'s vCPU projection unchanged:
`SchedSetAffinity` is the one scheduler op with a `target`, gated by
`caller == target ∨ controls[caller][target]` — so the guard forces any target `b` may write to
be `≠ a`; the caller-only ops write only `b`'s own rows.

**The finding — not every channel borrows from a relational invariant.** The memory channel's
locality borrows from `MisownedGrantMap`, the signal channel's from reciprocity — both *state*
invariants bridging two sides. The authority channel's locality comes **directly from the
transition guard** (design-lesson #9: authorization is a *guard*, not a *state invariant*): the
`SchedSetAffinity` check *is* the write-restriction, so there is no two-sides bridge to prove.
That makes it the **simplest** of the three (3 lemmas, zero iterations) — a datapoint that
per-channel local respect is not uniformly hard, and that the shape depends on whether the
channel is guarded by a state invariant or a transition precondition.

## 5b. The creation channel, ∀-N (green) — the four direct channels, two-and-two

The fourth direct channel: **creation**. `hv-verify/verus/unwinding_create.rs` (2 verified, 0
errors, **first try**) proves, over **arbitrary domain count**, that `DomainCreate` by a `b` with
no creation channel to `a` (`¬(may_create[b] ∧ ¬live[a])`) leaves `obs(a)` unchanged. The whole
content is `life[a]`: creation *adds no resources* (a `Dead` slot is a clean shell —
`DeadDomainNotClean`), writing only `life[target]`, `may_create[target]`, and the creator's
`Root` edge, of which only `life[target]` is in `obs`. And `life[a]` is guard-protected — the
`DomainCreate` guards (`may_create[b] ∧ target Dead`) force any slot `b` may lift to be `≠ a`
(else the guard's `may_create[b]` and the channel's `live[a]` would contradict the guard's
`¬live[target]`). Non-vacuity: dropping the channel hypothesis makes Verus reject it.

**Creation is the *second* guard-channel** — so the four direct channels split cleanly
**two-and-two**:

| direct channel | proof | locality borrows from | effort |
|---|---|---|---|
| memory | `frame_lemma.rs` | `MisownedGrantMap` (state invariant) | ~5 lemmas |
| signal | `unwinding_signal.rs` | event-channel reciprocity (state invariant) | ~2 lemmas / 2 iters |
| authority | `unwinding_control.rs` | the `SchedSetAffinity` **guard** (#9) | ~3 lemmas / 0 iters |
| creation | `unwinding_create.rs` | the `DomainCreate` **guards** (#9) | ~2 lemmas / 0 iters |

The shape of a channel's local-respect proof is *predicted by how the channel is authorized*:
state-invariant-guarded channels (memory, signal) need a two-sides bridge lifted from that
invariant; transition-guarded channels (authority, creation) get their write-restriction straight
from the guard and are strictly simpler. **All four direct channels are now discharged ∀-N.**

## 6. Honest scope, cost read, and the fork

**What the spike establishes.** The property definition (`obs`, `⇝`, local respect, the
intransitive teardown term) is decided and **validated on the real code** (millions of unauthorized
checks, no violation), the tooling call is made (Verus, bridge-first), and **both axes** are green:
the enumerator bridge (real code, small size, all transitions) and one Verus unwinding lemma
(∀-N, second seam). Non-interference on this model is **tractable, not a research dead-end.**

**What remains for full Tier D.** Whole-system non-interference is *one local-respect lemma per
transition class over the whole `obs(a)` projection*, assembled compositionally (plus the step- and
output-consistency conditions, both light given `~_a` = `obs`-equality). **All four direct channels
are done** — memory (`frame_lemma.rs`), signal (`unwinding_signal.rs`), authority
(`unwinding_control.rs`), creation (`unwinding_create.rs`). The only obligations left are the
intransitive **`DomainDestroy` cascade** (the one genuinely multi-domain transition, whose write-set
spans a target's whole partner set — the honest unknown, and now the *sole* remaining lemma) and the
**compositional assembly** (glue the per-channel lemmas + the light step/output-consistency
conditions into whole-system non-interference).

**The cost read, plainly.** Tier D is **not** the person-months cliff it might have been. The
definition was the hard part and it is *done and validated*; **all four** per-channel unwinding
lemmas (~5, ~2, ~3, ~2 lemmas; zero-to-two iterations each) came in *easier* than Tier C's, and
their shape is now understood (state-invariant-guarded channels take a two-sides bridge;
transition-guarded channels are simpler). What is left is the `DomainDestroy` cascade — the genuine
unknown — plus assembly. Completing Tier D is a **finite, tractable program**: one hard-ish lemma
and the glue, not research-grade risk.

**The fork (the user's call).** Tiers A–C already make the safety **core** deductively proven ∀-N;
this spike shows Tier D's *"are we checking the right things"* capstone is reachable and its
property is *already validated on real code*. The remaining choice is whether to spend the few more
unwinding lemmas to make whole-system non-interference a **deductive theorem**, or to judge the
model-level diamond sufficiently established — the property is defined, validated exhaustively at
small size, and spiked ∀-N on two seams — and move to the metal (M3+). Either way, **these prove
the *model* (the pure brain); whether the *metal* enforces it is inherently M3+, outside this
program.**
