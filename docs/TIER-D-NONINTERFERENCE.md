<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Tier D — non-interference (the property definition + the bridge spike)

*Status: **integrity non-interference COMPLETE at the model level; confidentiality dual
characterized.** Property definition decided and validated on real code (the enumerator bridge);
every transition class proven ∀-N (five per-transition local-respect lemmas); the **unwinding
theorem** (`noninterference_theorem.rs`) assembles them into whole-system non-interference; and the
last mile (`step_consistency.rs`) discharges the derivable part of the confidentiality premise,
leaving a bounded, characterized read-closure residual (§5e). This is the deepest and last tier of the true-diamond program — the
"are we checking the **right** things" capstone. Tiers A–C prove the invariants hold in every
reachable state, ∀-N; Tier D proves those invariants **collectively imply real isolation**. Read
alongside `hv-sim/src/noninterference.rs` (the enumerator bridge), the five `hv-verify/verus/
unwinding_*.rs` + `frame_lemma.rs` (the per-transition lemmas), `noninterference_theorem.rs` (the
assembly), and `docs/TIER-C-SPIKE.md` (the tier before). These prove the **model** (the pure brain);
whether the **metal** enforces it is M3+, outside this program.*

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

## 5c. The `DomainDestroy` cascade, ∀-N (green) — the multi-domain obligation

The last and hardest transition class: the only *genuinely multi-domain* one.
`hv-verify/verus/unwinding_destroy.rs` (7 verified, 0 errors) proves it over **arbitrary domain
and partner count** — the §2.4 axis with no size cutoff. `DomainDestroy(c)` tears `c` down and its
cleanup **cascades to `c`'s partners**, so a step by `b` (with `controls[b][c]`) can move a *third*
domain `a`'s observation — the intransitive flow the bridge found (§4). Its compound teardown
touches **three** components of `obs(a)`, and every touch is conditioned on `a`'s reach to `c`:

| sub-op | touches `obs(a)` iff | shape |
|---|---|---|
| `close_all` / `clear_unbound_into` | `a` holds a port toward `c` (`Interdomain{c}` / `Unbound{c}`) | guard-shaped (`remote == c`) |
| `revoke_grants_to` / `drain_maps_of` (row) | `a`'s grant row has grantee `c` | guard-shaped (`grantee == c`) |
| `drain_maps_of` (frame refs) | `c` held a map over `a`'s frame | **borrows from the grant `map`-identity** |

The proof discharges all three (`port_preserved`, `grant_row_preserved`,
`drain_preserves_frame_refs` + `no_c_map_over_a_frame`) and the **intransitive-channel heart**
(`no_channel_no_reach_to_c`): `¬(b ⇝ a)` plus an authorized destroy of `c` (`b == c ∨
controls[b][c]`) implies `a` has no reach to `c` — the peer case excluded by the teardown-reach
term, the self case (`c == b`) by the direct grant/port channels. The *reverse* direction (`a`
referencing `c`'s frames) cannot arise past a proceeding destroy: `DomainBusy` refuses teardown
while any foreign domain holds a live map of, or a page-table link into, `c`'s frames
(`hypervisor.rs:1178`).

**The finding — the cascade composes *both* channel kinds in one transition.** Its port and
grant-revoke sub-ops are guard-shaped (a filtered clear on a directly-readable key); its
drain→frame-reference sub-op borrows from a relational invariant (the grant `map`-identity: a map
by `c` over `a`'s frame ⟹ `a` granted to `c`) via a `Seq`-induction filtered-count-equality,
frame-lemma-shaped. So the two-and-two taxonomy of §5b reappears *within* the single hardest
transition. Effort: ~7 lemmas — more than any single direct channel (the compound write-set + the
`Seq` induction), but it went green without the multi-week grind the caveat warned of.
Non-vacuity validated: dropping the `map`-identity hypothesis, or the teardown-reach hypothesis,
makes Verus reject. **With this, every transition class of Tier D is discharged.**

## 5d. The compositional assembly — the whole-system theorem (green)

The capstone: the per-transition lemmas each prove **local respect** for one `step` class; the
**unwinding theorem** (Goguen–Meseguer / Rushby — the method seL4-infoflow and CertiKOS use)
assembles them into the top-level property over *arbitrary executions*.
`hv-verify/verus/noninterference_theorem.rs` (5 verified, 0 errors) models the abstract transition
system (`obs`, `step`, `actor`, `interferes`, `run`) and proves two theorems:

* **Theorem A — local respect lifts to whole executions** (from **local respect** alone): a domain
  `a` sees a *constant* observation across any execution whose actions are all by principals that
  don't interfere with it. *Unrelated activity, of any length, is invisible to `a`.* This is the
  direct assembly of the five per-transition lemmas — and it is **complete**, because local respect
  is exactly what those five discharge (each for one `step` class, covering every `HvCall`).
* **Theorem B — the unwinding theorem** (from local respect + **step consistency**): two executions
  that start `obs(a)`-equivalent and agree, at each step, on the acting domain's observation, stay
  `obs(a)`-equivalent throughout. *`a`'s view is determined entirely by the inputs authorized to
  flow to it — it leaks nothing about the rest.* Step consistency (`obs(a)`'s successor is a
  function of `obs(a)` and the actor's observation — projection-determinism) is the remaining
  unwinding premise, light given `~_a` = `obs`-equality.

The two conditions are proven to *imply* the global property by trace induction; the five
per-transition lemmas discharge local respect for the concrete system, and step consistency is the
projection-determinism premise. Non-vacuity: dropping either premise makes Verus reject the
corresponding theorem.

## 5e. The last mile — step/output consistency, and the integrity/confidentiality split

`hv-verify/verus/step_consistency.rs` (3 verified, 0 errors) discharges what is cleanly derivable
of Theorem B's step-consistency premise and pins down the irreducible residual — the honest content
of "the last mile."

* **The reduction** (`step_consistency_off_channel`): from local respect *alone*, step consistency
  holds for every step whose actor does not interfere with `a`. So the premise is never needed
  off-channel — it reduces to the **interfering-actor** case (the confidentiality obligation is
  only ever about authorized flows). The output-side analogue (`output_consistency_off_channel`)
  holds the same way.
* **The write direction** (`factored_step_is_consistent`): step consistency holds for every
  **write** channel — a principal `b`'s *authorized effect on `a`* (mapping a grant `a` offered →
  `a`'s frame refs `+1`; signalling a channel `a` is party to → `a`'s pending bit) is computed from
  `a`'s state and `b`'s, both observed, so it factors through `obs(a) + obs(actor)`.

**The finding — the residual is the confidentiality dual.** What does *not* factor through
`obs(a) + obs(actor)` is a domain reading a **partner's** state it is authorized to see — `a`
itself mapping/copying a grant a partner `c` offered it, whose success reads `c`'s frame ownership
(the `StaleGrant` check), state in neither `obs(a)` nor `obs(actor == a)`. This is the exact **dual
of local respect**: local respect is *integrity* — no unauthorized principal **writes** `obs(a)` —
and it is **proven ∀-N**; the residual is *confidentiality* — no unauthorized state is **read** into
`a`'s view. Discharging it fully requires refining the observation to its **read-closure** (`obs(a)`
extended with the partner state `a` holds a read-capability for — the frames behind grants `a` has
mapped), after which the read factors and step consistency closes. That refinement, and
re-validating the channel relation against it, is a **bounded, well-characterized next arc** — the
confidentiality direction of the property. **The integrity property the tier set out to prove
(Theorem A — "`a` can't be *affected* except through authorized channels") stands complete without
it.**

## 6. Honest scope, cost read, and the fork

**What the spike establishes.** The property definition (`obs`, `⇝`, local respect, the
intransitive teardown term) is decided and **validated on the real code** (millions of unauthorized
checks, no violation), the tooling call is made (Verus, bridge-first), and **both axes** are green:
the enumerator bridge (real code, small size, all transitions) and one Verus unwinding lemma
(∀-N, second seam). Non-interference on this model is **tractable, not a research dead-end.**

**Tier D's integrity non-interference is complete at the model level; the confidentiality dual is
characterized.** Whole-system non-interference is *one local-respect lemma per transition class over
`obs(a)`*, assembled by the unwinding theorem (§5d). Every part of the **integrity** property is
done: the property definition (validated on real code by the bridge, §4); the five per-transition
local-respect lemmas — memory (`frame_lemma.rs`), signal (`unwinding_signal.rs`), authority
(`unwinding_control.rs`), creation (`unwinding_create.rs`), the `DomainDestroy` cascade
(`unwinding_destroy.rs`); and the compositional assembly (`noninterference_theorem.rs`), whose
Theorem A ("`a` can't be *affected* except through authorized channels") rests on local respect
alone. The **confidentiality** dual (Theorem B, "`a` can't *learn* anything unauthorized") reduces
(§5e) to step consistency on interfering actors, which is proven for the *write* direction and
whose sole residual is the *read* direction — a bounded, well-characterized arc needing an `obs`
read-closure.

**The cost read, plainly.** Tier D was **not** the person-months cliff it might have been. The
definition was the hard part and it is *done and validated*; all five per-transition unwinding
lemmas (~5, ~2, ~3, ~2, ~7 lemmas) came in *easier* than feared, their shape is understood
(state-invariant-guarded channels take a two-sides bridge; transition-guarded channels are simpler;
the cascade composes both); the assembly went green in one arc; and the last mile resolved cleanly
into "integrity: done; confidentiality: characterized, read-closure residual." **The true-diamond
program A→D is complete at the model level for integrity non-interference** — Tiers A–C prove every
invariant holds ∀-N, Tier D proves they collectively imply *isolation* (nothing unauthorized affects
a domain). Two honest horizons remain: the **confidentiality read-closure** (finishing Theorem B —
a bounded model-level arc), and the **metal** (M3+, ARM-first QEMU — carrying the model guarantees
onto hardware, an inherently new program outside true-diamond).

**The fork (the user's call).** Tiers A–C already make the safety **core** deductively proven ∀-N;
this spike shows Tier D's *"are we checking the right things"* capstone is reachable and its
property is *already validated on real code*. The remaining choice is whether to spend the few more
unwinding lemmas to make whole-system non-interference a **deductive theorem**, or to judge the
model-level diamond sufficiently established — the property is defined, validated exhaustively at
small size, and spiked ∀-N on two seams — and move to the metal (M3+). Either way, **these prove
the *model* (the pure brain); whether the *metal* enforces it is inherently M3+, outside this
program.**
