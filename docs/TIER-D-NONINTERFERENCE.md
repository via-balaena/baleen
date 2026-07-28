<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Tier D — non-interference (the property definition + the bridge spike)

*Status: **Both directions established at the model level; the generic premises are now DISCHARGED
for a concrete instantiation (§5g) — GAP-C fully closed.** Property definition decided and validated
on real code (the enumerator bridge); every transition class proven ∀-N (five per-transition
local-respect lemmas); the **unwinding theorem** (`noninterference_theorem.rs`) assembles them into
whole-system non-interference; the last mile (`step_consistency.rs`) reduces the confidentiality
premise to the read direction; and the **read-closure** (`read_closure.rs`) discharges that via
`obs⁺` and the extended relation `⇝⁺` (§5e–§5f). **§5g (`noninterference_instantiation.rs`, 14
verified) turns the meta-theorem's `local_respect()`/`step_consistent()` *premises* into discharged
theorems over a concrete carrier for ALL FIVE transition classes (including the `DomainDestroy`
cascade), closing the "paper composition" GAP-C and forcing four `obs` corrections (see §2.1 + §5g).**
This is the deepest and last tier of the true-diamond program — the
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

  > **Correction (2026-07-27, forced by the ⑥ guard audit — §4b/F4).** "Excluding it keeps the
  > property *true*" is **wrong for the confidentiality direction**, and the word *abstracts* was
  > doing work it cannot do. `sched::run` refuses with `SchedError::PcpuBusy` when the named pCPU is
  > occupied, so occupancy is not merely a *timing* channel — it is an **explicit-flow** one, read
  > by a guard and reported to the caller as an error. Leaving it out of `obs` does not make step
  > consistency hold; it makes it **false**, with a depth-5 counterexample on real code
  > (`unpartitioned_pcpus_break_step_consistency`). It went unseen for so long because no
  > step-consistency config had ever enabled `sched`. The repair is **partitioning**, not
  > observation — the same class as ②′-(b)'s mediated allocator: pin each domain to its own pCPU
  > (`mediated_pcpus`), and a `PcpuBusy` refusal can only name the caller's *own* vCPU, whose
  > placement `obs(a)` already carries. Read this exclusion as **"abstracted *and* partitioned"**;
  > the timing-channel scope statement above stands, but it was never sufficient on its own.
- **Authority is out** (`may_create[a]`, the `controls` matrix — outgoing and incoming). Authority
  is `a`'s *power over others*, not others' ability to corrupt or read `a`. When `b` delegates a
  capability *to* `a`, that changes `a`'s authority but touches **none** of `a`'s resources — and
  its correctness is already governed by the Tier-C control-forest invariants
  (`ControlEdgeOrphaned` etc.). Keeping authority in `obs(a)` would flag every legitimate
  delegation as interference. So authority delegation is governed by Tier C; `obs(a)` is `a`'s
  *resource* surface.

  > **Correction (2026-07-27, forced by the instantiation — §5g).** This exclusion is **too
  > strong** for the *confidentiality* direction. Discharging `step_consistent` as a machine-checked
  > theorem (`noninterference_instantiation.rs`) requires that a domain observe **its own incoming**
  > authority — `may_create[a]` (creation) and its controllers `controls[·][a]` (affinity). Reason:
  > `DomainCreate` flips `life[a]` iff `may_create[creator]`, and `SchedSetAffinity` on `a`'s vCPU
  > fires iff `controls[caller][a]`; under the authority-*excluding* `obs`, those bits are in neither
  > `obs(a)` nor `obs(actor)`, so two runs agreeing on the documented observation diverge in `a`'s
  > view — **Theorem B is *false* for the documented `obs`**, and Verus rejects it (validated by a
  > probe, and reproducible by deleting the field from `Obs`). What stays correct: excluding `a`'s
  > authority *over others* (outgoing power). The fix is narrow: `obs(a)` carries `a`'s own *incoming*
  > authority (its create bit, who controls it) — a resource-like fact about `a`'s slot.

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

We did not guess this — **the bridge found it** (§4).

**Since ②′-(c) the term has a second, inbound half** (`Channels::teardown_borrow`):

> `∃ c: controls[b][c] ∧ (a holds a live grant map over one of c's frames ∨ a has a page-table
> edge into one)`.

Originally this was unnecessary, and the reason is instructive: a live foreign hold on `c`'s frames
made destroy *refuse* (`DomainBusy`), so the only reachable effect on `obs(a)` was the cleanup of
`a`'s **own outbound** references to `c` — exactly what the first half authorizes. Replacing the
refusal with force-reclaim (§4a-(c)) made the inbound direction reachable: teardown now breaks what
`a` *borrowed from* `c`, and `a` observes the loss (a held map leaves its handle-indexed maptrack; a
severed edge returns its own table's self-reference, moving its frame refcount). Same intransitive
`b ⇝ c ↔ a` shape, with the `a↔c` reference pointing the other way. The bridge found this half too —
it is the integrity twin of finding #3 (the read direction), and
`dropping_teardown_borrow_is_caught` is its non-vacuity witness.

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

### 4a. The confidentiality dual — step consistency and the `DomainDestroy` read direction (green)

Local respect (above) is the **integrity** half. The **confidentiality** half — *step consistency*,
the counterpart of §5g's `step_consistent_holds` — is now also swept on real code
(`noninterference::check_step_consistency`): `obs⁺(a)` after a step is a **function of**
`(obs⁺(a), obs⁺(actor))` before it (two states `a` and the actor cannot distinguish go to the same
successor). It runs over `obs⁺` = `obs` plus (i) the **read-closure** — the grants `a` is a
*grantee* of, with each grantor, frame, and the **StaleGrant status** `owner_of(frame) == grantor`
(the boolean `a`'s `grant_map` returns, *not* the owner's identity — see the fidelity note below) —
and (ii) `a`'s own **authority**.

This is where the **`DomainDestroy` read direction** (§5g finding #3) is validated on real code:
destroying `a`'s grantor `c` runs `grant::revoke_all(c)`, dropping `a`'s read-cap, and the sweep
confirms two `obs⁺(a)`-equal states lose it *together* (test `the_destroy_read_direction_is_exercised`
shows the flow is live; `step_consistency_holds_on_real_code` shows it holds, non-vacuously, over
tens of thousands of multi-state classes). Two findings the sweep independently reproduces:

* **The read-closure is *not* a local-respect surface.** A grantor freely *creating* an offer to `a`
  moves `a`'s read-caps, and that is not integrity interference (a domain cannot stop others revealing
  themselves to it). So the read direction is confidentiality, not integrity — it belongs to step
  consistency, and adding read-caps to the *local-respect* `obs` would wrongly flag every grant.
* **`obs⁺` must carry the observer's own authority** (§5g finding #1): strip `may_create[a]` / the
  `controls` rows back out and step consistency *breaks* on a `DomainCreate` (test
  `dropping_authority_from_obs_plus_breaks_step_consistency`) — the enumerator's confirmation that the
  confidentiality theorem is false under the authority-excluding observation.

**Read-closure real-code fidelity — the boolean, not the owner (②′-(a), landed).** The read-cap
records the *StaleGrant status* `owner_of(frame) == grantor`, not the raw owner. `a`'s cross-domain
map/copy learns exactly whether the grantor still owns the frame (`Ok` vs `Err(StaleGrant)` in
`hypervisor::grant_map`) — never *who* owns it. Under the real code's **dynamic** frame ownership
(`P2mAllocate`) and ownership-free grant *creation* (`GrantAccess` needs none), exposing the raw
owner leaks a *third* domain's identity into `a`'s read-cap: a four-domain step-consistency sweep
finds a depth-4 counterexample on `GrantAccess` (two states agreeing on `obs⁺(a)`/`obs⁺(actor)` but
differing in which invisible third domain owns the granted frame). The boolean collapses that
identity — pinned by the unit test `read_cap_records_stale_status_not_owner_identity`. (The Verus
instantiation keeps the raw owner, sound *there* because its abstract model has static ownership and
no grant-creation step; the bridge carries the tighter boolean because it runs against the dynamic
real code — the honest bridge↔composition division, `read_closure.rs` fidelity note, §5g.)

* **Allocation contention (②′-(b), RESOLVED — the mediated allocator).** Even with the boolean, a
  four-domain (and a three-domain-with-p2m) sweep finds a `P2mAllocate{mfn}` counterexample: whether
  the actor's allocation of a shared machine frame *succeeds* depends on whether another domain
  already grabbed that frame — a race for a shared resource, invisible to grantor and grantee, that
  flips the StaleGrant boolean. **This is a model looseness, not a real Baleen channel.**
  `hv-core::allocate(owner, mfn)` lets a guest name an arbitrary machine frame first-come-first-owns,
  whereas a real hypervisor *mediates* machine-frame assignment (guests request via gfn; the host
  maps gfn→mfn from disjoint per-domain pools — the gfn=mfn fence, design-lesson #14e). The
  contention is the storage-side analogue of the pCPU-occupancy covert channel §2.1 already
  abstracts. **Resolution: model the mediation** — the enumerator's `mediated_frames` flag emits
  `P2mAllocate{mfn}` only for `mfn`'s partition-owner (`mfn % domains == caller`), so each guest
  draws from its own disjoint pool and no two domains race for one frame. Under it, step consistency
  **holds** over four domains with dynamic p2m + grants + create/destroy, non-vacuously (tens of
  millions of key-classes: `step_consistency_holds_with_a_mediated_allocator`). The mediation is
  *load-bearing*, not a config that is trivially safe: turn `mediated_frames` off and the same config
  breaks with a `P2mAllocate` counterexample (`an_unmediated_allocator_breaks_step_consistency`, deep
  — the "remove the fix → CE" discipline). This keeps the allocation channel's step consistency
  **checked**, not declared out of scope. Off by default, so the Tier-A/B soundness + saturation
  witnesses keep their exact calibration.
* **Grant-handle identity (②′-(d), RESOLVED — the per-domain maptrack).** With destroy enabled the
  next counterexample was `GrantUnmap{handle}`: a domain holding a writable *and* a read-only map of
  one grant, mapped in opposite order, has an identical held-map *set* but `GrantUnmap{handle:0}`
  drops different maps, diverging the grantor's `writable_maps`. The handle layout is behaviourally
  live (`state_key` always kept it), but `obs` had flattened it to a set. Making `obs` handle-indexed
  is faithful **only if handles are per-domain**: `hv-core`'s grant map table was a *global* slot
  pool (`System.maps`), so a slot index leaked the global allocation order — another domain's
  map/unmap activity — a spurious A←B covert channel that broke local respect. **Resolution
  (strongest foundation — fix the model, not the observation):** the grant **handle namespace is now
  per-domain** (Xen-faithful — each grantee names its mappings in its own namespace). Each `Mapping`
  carries a per-domain `handle`, assigned as the lowest free handle *among that grantee's own live
  mappings* (`alloc_handle` scans only that domain's maps), so a domain's handle numbers depend on
  its own history alone, never on another domain's. The mappings stay in **one flat table**
  (`System.maps`) for single-pass refcount checking — the physical slot is storage, not the handle —
  which is deliberately why CBMC stays tractable: a nested per-domain `Vec<Vec<_>>` blows up the Kani
  grant harness (8 GB / 8 min), whereas the flat table + a handle field verifies in ~6 s, and the
  refcount content is untouched (a per-grant-entry count over the flat table that reads neither
  grantee nor handle). `obs` records `a`'s held maps indexed by `a`'s own handle; local respect *and*
  step consistency then both hold over four domains with dynamic p2m + grants + create + destroy
  (`step_consistency_holds_per_domain_handles_with_destroy`). Cross-domain handle confusion becomes
  unrepresentable (the `NotYours` error is gone). All Kani harnesses and Verus proofs (incl.
  `refcount_mismatch.rs`) stand verbatim.
* **`DomainBusy` (②′-(c)) — CLOSED by force-reclaim.** `DomainBusy` (which refused a destroy while
  a foreign domain mapped `c`'s frames) depended, with a *fourth* domain as that mapper, on state
  neither `a` nor the actor observes — so at ≥4 domains step consistency for the destroy channel
  rested on the instantiation's over-approximation of `DomainBusy` (§5g). It was masked behind (b)
  and (d); with those closed it surfaced as the last read-closure fidelity edge — and, unlike
  (a)/(b)/(d), it was a *design* question, not an observation refinement.

  **Decision: force-reclaim.** `domain_destroy` no longer refuses. Past the authority gate it always
  succeeds, draining every foreign grant map over the target's frames
  (`grant::drain_foreign_maps_of`) and severing every inward foreign page-table link
  (`p2m::unlink_all_into`) before reclaiming them; `HvError::DomainBusy` is removed outright, so no
  code path can reproduce the refusal. Three reasons, in order of weight:

  1. **The refusal was a denial of service.** One unprivileged mapper holding one grant map kept a
     domain alive indefinitely, and the target's controller had no way to make it let go.
  2. **It was an unobservable-state channel** — the step-consistency residual above. Draining closes
     it *by construction*: the destroy is a total function of the actor's own observation, so there
     is nothing for a hidden fourth domain to modulate.
  3. **The proofs already modelled it this way.** `noninterference_instantiation.rs`'s destroy
     carrier drops every map over a `c`-owned frame (`drain_pred`), documented as a sound
     over-approximation of `DomainBusy`. Force-reclaim makes the code *coincide* with the
     already-proven model instead of merely being covered by it — the abstraction adopted to keep
     the proof honest turned out to be the right semantics.

  **What it cost, and what it forced.** A foreign mapper loses a page it was using — but never
  unsafely: its grant handle goes inactive (a later unmap is `BadHandle`, never a double release)
  and its page-table entry becomes a hole (a fault, never a dangling reference to a reclaimed
  frame). And it *forced a correction to the channel relation*: making the reclaim reachable created
  an integrity flow the outbound-only teardown term did not name, which is the `teardown_borrow`
  half added in §2.1. That correction is the arc's real finding — the same pattern as GAP-C's four
  (design-lesson #57): changing the code to close one channel surfaced another that the old
  semantics had made unreachable, and only the machine-check found it.

  **Evidence.** `force_reclaim_closes_the_busy_channel_grant_map_direction` and its
  `..._foreign_link_direction` twin pin the closure directly on real code (targeted, not swept: the
  configuration sits at ~depth 9, past the sweep's reach); the enumerator's `forced_reclaims`
  counter witnesses the new path is genuinely exercised rather than vacuously absent; all 14 Verus
  proofs and all Kani harnesses stand verbatim.

* **The revoke guard's foreign-linked status (②′-(e)) — CLOSED by observing it.** Ruling on the
  asymmetry (c) left behind — `GrantEndAccess` still refuses (`InUse`) while a foreign page-table
  entry relies on a grant, though `DomainDestroy` now force-reclaims — turned up a **third residual
  of the same family**. The refusal predicate is `p2m::is_foreign_linked_by(frame, grantee)`:
  *which* grantee linked. The grantor could not distinguish that from its observation, because two
  grantees of the same frame move its aggregate `refs` identically. So two `obs⁺(grantor)`-equal
  states had `GrantEndAccess{gref}` refuse in one and succeed in the other — step consistency false
  for the revoke channel, at a depth (~7: four domains, two grants of one frame, an allocation, a
  pin and a link) the sweep never reaches.

  **Resolved the OPPOSITE way to (c), and the contrast is the finding.** Both are guards whose
  predicate the caller could not fully observe, but they differ in *whose* state the guard reads:

  | | `DomainBusy` (c) | revoke's foreign-link guard (e) |
  |---|---|---|
  | Guard reads | the **target's** frames | the **caller's own** frame + its own grant |
  | Caller entitled to observe it? | **No** | **Yes** |
  | Refusal strands a resource? | **Yes** — target's frames unreclaimable, controller powerless | **No** — grantor keeps the frame, can retry |
  | Fix | **remove the guard** (force-reclaim) | **observe the predicate** |

  So the rule the two jointly establish: **a refusal conditioned on state the caller can see is a
  legitimate error; one conditioned on state it cannot see is a covert channel.** The repair
  follows from *which* — remove the guard when it reads another principal's state, surface the
  predicate when it reads the caller's own. Consistency of *mechanism* between the two operations
  was never the right target; consistency of *principle* is.

  Fix: `obs`'s grant rows gain a per-row foreign-linked boolean — the faithful observable, since the
  grantor learns exactly that bit off `InUse` vs `Done` (design-lesson #59). **Model-side only**:
  `hv-core` behaviour is unchanged, so no proof or harness moves. Only a domain the grantor has
  granted to can move the bit, which the consent channel already authorizes, so local respect is
  unaffected (deep sweeps re-run green). Pinned by
  `the_revoke_guards_foreign_linked_status_is_in_obs`.

At ≤3 domains **without dynamic p2m** the sweep is clean (the committed `ni_cfg3` has no allocation),
and the deep three-domain sweep runs in `deep-verify.yml`.

### 4b. ⑥ — the guard-observability audit (the rule of (c)/(e), applied to *every* guard)

②′-(c) and (e) established a rule (design-lesson #62) that is checkable against every guard in the
system, so ⑥ checks them all. Three had been audited before it — `P2mAllocate` contention (b),
`DomainBusy` (c), the revoke foreign-link guard (e) — each found the hard way, one at a time. The
audit found **four more**, and, first, a defect in the checker that had hidden all four.

**F0 — the sweep was checking a strictly weaker property than the obligation it bridges to.**
`check_step_consistency_with` skipped the `observer == actor` case. The obligation in
`noninterference_instantiation.rs::step_consistent` quantifies over **every** `a: Dom`, with no
`a != actor(t)` side condition — and the self-observer case is a real one: the actor's own successor
observation must be a function of its own observation. Every guard whose refusal the *caller* reads
back lives in exactly that case, which is why the sweep had never seen one. With the skip removed the
sweep is strictly stronger, and it produced counterexamples at **depth 2–5** — the four below were
not deep, they were invisible. *(Method note: this inverts ②′'s experience, where the defects genuinely
sat at depth 7–9 and needed hand-built probes. Both failure modes are real, and "the sweep is green"
is only as strong as the quantification the sweep actually runs — check the checker against the
theorem statement, not against its docstring.)*

**F1 — peer liveness (`AlreadyAlive` and the `reject_dead_target` family) — RESOLVED by observing.**
Four guards read a *named peer's* liveness and report the result to the caller: `AlreadyAlive` on
`DomainCreate{target}`, and `NotAlive` on `GrantAccess{grantee}`, `EvtchnAllocUnbound{remote}` and
`ControlGrant{to}`. Two `obs⁺(caller)`-equal worlds differing only in whether an unrelated creator
raised an unrelated slot take `DomainCreate{target}` to different successors (the success writes
`controls[caller][target]`, which `obs⁺` does carry) — step consistency false, at **depth 2**.

None can be *removed*: each is what keeps `DeadDomainReferenced` / `ControlEdgeDeadEndpoint` standing
invariants, so force-completing would let a reference outlive the incarnation it named (domid-reuse
unsoundness), or — for `AlreadyAlive` — silently reincarnate a *live* peer. Refusal strands nothing.
So by #62 this is the observe case: `obs⁺` gains every domain's liveness.

**What is new is the quadrant.** (c) was "another's state + strands a resource ⇒ remove"; (e) was
"caller's own + strands nothing ⇒ observe". This is the fourth cell — **another principal's state,
strands nothing** — and its repair is neither: the predicate is surfaced, but because the state
belongs to a third party that makes it a **declared disclosure**, not a channel closed by
construction. Stated plainly: **domain liveness is public in Baleen.** Any domain can probe any
slot's liveness with one hypercall, gated by no capability. `obs⁺` is the upper bound on what `a` can
learn, so it must say so; whether Baleen *should* partition the domid namespace (the mediation route,
as for frames and pCPUs) is a separate design question, recorded in the honest ledger and not taken
here — it would need a new naming-authority axis in `hv-core`, which is a program, not a rung.
Pinned depth-independently by `the_already_alive_guard_is_observed` (the (c)/(e)-style two-state
probe) and by `dropping_peer_liveness_from_obs_plus_breaks_step_consistency`, which also asserts the
counterexample is a *self-observer* one — so reinstating F0's skip fails the test.

**F2 — the inbound invitation closure (`EvtchnBindInterdomain`) — RESOLVED by observing.**
`bind_interdomain` refuses unless the named remote port stands `Unbound{remote: caller}`, so a peer's
half-open invitation decides whether the caller gains an `Interdomain` port — state that belongs to
the peer, and that `obs(caller)` cannot show. This is the **event-channel twin of the grant
read-closure**, and it gets the same treatment for the same reason: the observed state is an
invitation the peer deliberately addressed to `a`, exactly as a grant row naming `a` as grantee is,
so it is a *confidentiality*-only component (a peer revealing itself to `a` is not integrity
interference — design-lesson #58) and stays out of the local-respect `obs`. Only the invited port's
`(owner, port)` identity is recorded, which is all `bind_interdomain` names. Pinned by
`dropping_invitations_from_obs_plus_breaks_step_consistency`.

**F3 — control-edge provenance — RESOLVED by observing, and a coverage hole behind it.**
`ControlGrant`/`ControlRevoke` had `delegate: false` in **every** NI config, so the delegation guards
had never been swept for local respect *or* step consistency. Turning delegation on produced a
counterexample immediately: `obs⁺` recorded control edges via `Hypervisor::controls()`, a **boolean
presence** projection, but a `Root` edge (`a` created `c`) survives its delegator's teardown while a
`Via` edge (`a` was delegated control of `c`) is cascaded away by `sweep_orphaned_control_edges`. Two
present-but-differently-rooted edges are `obs⁺`-equal yet take `DomainDestroy{target: delegator}` to
different successors. Exactly ②′-(e)'s shape — an aggregate projection hiding the detail the
transition reads, as `refs` hid *which* grantee had linked.

Fix: `obs⁺` records `Root` vs `Via` for `a`'s **outgoing** edges. The delegator's *identity* inside
`Via(d)` is deliberately **not** recorded — `a` is passive in `ControlGrant{to: a}` and learns no `d`
from any outcome, so recording it would over-approximate the observable exactly as the raw frame
owner did in ②′-(a). The **incoming** row stays a boolean for the same reason. Pinned by
`dropping_control_provenance_from_obs_plus_breaks_step_consistency` and
`step_consistency_holds_over_the_delegation_forest`.

**F4 — pCPU contention (`SchedRun` → `PcpuBusy`) — RESOLVED by partitioning, and it corrects §2.1.**
`sched::run` refuses when the named pCPU is already occupied, a guard that reads **which other domain
is running** — precisely the global pcpu-occupancy vector §2.1 excludes from `obs`. That exclusion
was documented as an *abstraction*; the audit shows the word was doing work it cannot do.
**Abstracting a channel out of `obs` does not make step consistency hold — it makes it false.** The
counterexample is concrete: `SchedRun{vcpu:0, pcpu:0}` by dom0 succeeds when dom1 does not occupy
pcpu0 and returns `PcpuBusy` when it does, from two `obs⁺(0)`-equal states. It had never been seen
because **`sched: false` in every step-consistency config** — the scheduler had been swept for
invariant preservation (Tiers A–C) and for local respect, never for confidentiality.

The repair follows ②′-(b)'s precedent rather than #62's remove/observe fork, because it is the same
*class*: contention for a **shared resource nobody owns**. The guard cannot be removed (two vCPUs
cannot share a pCPU) and the occupant's identity is not the caller's to observe, so the resource is
**partitioned** instead — the enumerator's new `mediated_pcpus` flag emits `SchedRun{vcpu, pcpu}`
only for `pcpu`'s partition-owner, which is what real hypervisors implement as **pinning**. Under it
a `PcpuBusy` refusal can only name the caller's *own* vCPU, whose placement `obs(caller)` already
carries, and step consistency **holds** (`step_consistency_holds_with_partitioned_pcpus`). Load-bearing,
not trivially safe: turn the flag off and the same config breaks
(`unpartitioned_pcpus_break_step_consistency`, the "remove the fix → CE" discipline). Off by default,
so the Tier-A/B soundness + saturation witnesses keep their calibration. **§2.1's pcpu-occupancy
exclusion should now be read as "abstracted *and* partitioned", not "abstracted".**

**The rest of the inventory — clean, and now actually swept.** `BadDomain`/`BadVcpu` (constant index
range, no state read) · caller-liveness `NotAlive` (the caller's own, in `obs`) · `Denied` authority
(`may_create`/`controls`, in `obs⁺` since §5g findings #1/#4) · the `StaleGrant` seam check · the
`Unauthorized` foreign-link guard · grant `InUse`/`WrongState`/`Overflow` · `WxConflict` ·
`SpanConflict`. The last five had *also* never been step-consistency swept — every prior config ran
`levels: vec![]`, so no `P2mPin`/`P2mLink` ever fired — and are now covered green by
`step_consistency_holds_over_the_page_table_guards` (two page-table levels, so interior and leaf
entries both arise, with both shared resources partitioned so the known contention channels do not
mask what the config is for). The **async EL2 agent** (`RaiseVcpuVirq`, the one non-guest transition)
was the last such hole — `async_agent: false` in every step-consistency config, so it had been swept
for local respect since Phase I-1c but never for confidentiality — and it is clean
(`step_consistency_holds_with_the_async_agent`): the raise reads only the target's own
`(vcpu, virq)` port binding, with no guard over another principal's state.

**Config-flag coverage is now a first-class artifact of this section.** Four of the six holes ⑥ found
were not missing *code* but missing *transitions in the swept universe* — `delegate`, `sched`,
`levels`, `async_agent` all defaulted off in every step-consistency config, and a green sweep over a
universe that never emits a guard's transition says nothing about that guard. For each guard, name
the committed config whose universe emits it.

**All four repairs are model-side only — `hv-core` is untouched by ⑥**, so every Kani harness and
Verus proof stands verbatim. Local respect is re-run over the two universes ⑥ added to the
confidentiality side and holds under the **unchanged** channel relation
(`local_respect_holds_over_delegation_and_the_scheduler`): delegation moves only the `controls`
matrix, which the integrity `obs` deliberately excludes, and a peer's pCPU placement is likewise
outside `obs(a)`. So all of ⑥'s widenings are confidentiality-only, as design-lesson #58 requires —
no `Channels` term was needed for any of them.

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
referencing `c`'s frames) could not arise past a proceeding destroy *when this was written*:
`DomainBusy` refused teardown while any foreign domain held a live map of, or a page-table link
into, `c`'s frames. Since ②′-(c) it can — teardown force-reclaims those holds — and the flow is
named by the `teardown_borrow` half of the term (§2.1). The Verus file itself is unaffected: its
`obs` projects the grant-map reference population over `a`'s **own** frames, and the drain only
touches maps over `c`'s frames. The page-table half is outside that model entirely and rides the
real-code bridge; `unwinding_destroy.rs`'s header records the divergence.

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

## 5f. The read-closure — finishing the confidentiality direction (green)

`hv-verify/verus/read_closure.rs` (2 verified, 0 errors) discharges the residual §5e identified.
Refine the observation to **`obs⁺(a)`** = `obs(a)` plus, for every grant naming `a` as grantee, the
read-capability tuple `(grantor, frame, active, owner(frame))` — exactly what `a`'s
`GrantMap`/`GrantCopy` reads (the grant's activeness and grantee, and the `StaleGrant` ownership
check). Two lemmas close it:

* `read_outcome_factors` — **step consistency closes.** `a`'s cross-domain read succeeds iff the
  capability is active and the frame is still owned by the grantor — a function of the read-closure
  tuple *alone*. So two states agreeing on `obs⁺(a)` compute the same read outcome and successor:
  the residual case factors once the observation is read-closed.
* `read_cap_stable` — **local respect extends.** `obs⁺(a)` is preserved by any step whose principal
  is neither the capability's **grantor** (only the grantor can end/alter the grant) nor an
  **owner-changer** of its frame. Those two are exactly the **extended channel relation `⇝⁺`** — the
  confidentiality dual of the write channels (`c ⇝⁺ a` iff `c` controls what `a` reads: `c` offered
  `a` the grant, or `c` can re-own its frame).

With `obs := obs⁺` and `interferes := ⇝ ∪ ⇝⁺`, **both** unwinding conditions hold — local respect
(the five write-lemmas for `obs(a)` + `read_cap_stable` for the closure) and step consistency (the
write channels factor, §5e, + `read_outcome_factors` for the reads) — so the generic assembly
theorem (`noninterference_theorem.rs`) yields **full non-interference: integrity *and*
confidentiality**. Non-vacuity: dropping the ownership component of the read-closure, or the
grantor guard, makes Verus reject. **The confidentiality direction is closed; Tier D is complete at
the model level in both directions.**

## 5g. The concrete instantiation — discharging the premises (closing GAP-C)

*Status: **all five transition classes done — GAP-C fully closed (`noninterference_instantiation.rs`,
14 verified).***

§5d's assembly (`noninterference_theorem.rs`) proves the unwinding theorem over *uninterpreted*
`obs`/`step`/`actor`/`interferes`, taking `local_respect()` and `step_consistent()` as **premises**.
The per-transition lemmas (§5–§5c) and the read-closure (§5f) each discharge a *fragment* of those
premises — but over their **own** independent `uninterp` symbols. The composition ("the five lemmas
give `local_respect()`; §5e+§5f give `step_consistent()`") lived only in these docs; `step_consistent()`
was a bare `requires` never discharged for any concrete system. This is the adversarial review's
**GAP-C** ("a paper composition").

`hv-verify/verus/noninterference_instantiation.rs` closes it. It defines a **concrete** transition
system — a composite `Sys` state and *interpreted* `obs`/`step`/`actor`/`interferes` — and proves
`local_respect()` **and** `step_consistent()` as **theorems** (`local_respect_holds`,
`step_consistent_holds`), then re-runs the unwinding induction over the concrete definitions
(`ni_theorem_a`, `ni_theorem_b`) with **no free premise**. So the top-level conclusion — `obs(a)` over
any run depends only on principals authorized to affect `a`, integrity *and* confidentiality — now
stands as a closed Verus obligation for **all five** classes: creation, signal, consent (memory) +
the confidentiality read-closure, authority, and the **`DomainDestroy` cascade** (§5c) — the sole
multi-domain transition, touching four `obs` components at once (ports, grant rows, the frame-map
population, read-caps) and carrying the intransitive **teardown-reach** channel (`interferes` gains
`∃c. controls[caller][c] ∧ reach(a, c)`). The `map`-identity is threaded as a `wf` invariant and
proven preserved (`wf_step_destroy`) so the drain is owner-local; non-vacuity is validated (dropping
`teardown_reach` makes Verus reject `local_respect` at the `¬reach` step).

**The honest division (altitude discipline).** The instantiation closes the *composition* gap; it
does **not** re-derive that the carrier mirrors the real `Hypervisor` — that remains the enumerator
bridge's job (§3–§4, `local_respect_holds_on_real_code`), which checks the same `obs`/channel
relation on the real code at bounded size. So the chain is now three machine-checked links —
**fragments mirror real code (bridge) → fragments compose to the premises (instantiation, ∀-N) →
premises imply whole-run NI (meta-theorem)** — with no prose seam between them.

**Findings the machine-check forced** (the value of doing this deductively):
1. **`obs` must carry a domain's own incoming authority** — see the §2.1 correction. `step_consistent`
   is *false* for creation/affinity under the documented (authority-excluding) `obs`; Verus rejects
   it. Load-bearing (non-vacuity validated by a probe).
2. **The read-closure carries `owner(frame)`** — a domain mapping a grant it holds succeeds iff the
   grantor still owns the frame (`StaleGrant`), so `obs⁺` must expose that owner, else
   `step_consistent` fails for the read direction (non-vacuity validated by a probe). This is §5f's
   `obs⁺` made load-bearing, not decorative.
3. **Teardown-reach extends to the read direction**: destroying `a`'s *grantor* alters `obs⁺(a)`, so
   the intransitive reach term carries a read-direction addend the original §2.4 (pre-`obs⁺`) lacked.
   `reach(a, c)` is `a→c port ∨ a→c grant ∨ a reads-from c` — the third disjunct discharges the
   read-cap component of the cascade.
4. **The actor observes its own *outgoing* destroy authority** (forced by `DomainDestroy`'s
   `step_consistent`): `destroy_guard` reads `controls[caller][c]` — `caller`'s power over the
   *target*, not over `a`, so it is in neither `obs(a)` nor `obs(caller)` under the incoming-only
   §2.1 authority, and two runs agreeing on the documented `obs` disagree on whether the destroy
   fires. The fix (the outgoing analogue of finding #1): `obs(a)` carries `controls[a][·]`. Also, the
   `DomainBusy` no-foreign-map precondition is a `c`-frames property invisible to `a`/`caller` and
   would break `step_consistent` the same way; the carrier instead has the drain *clean up* maps over
   `c`'s frames — then a sound over-approximation of `DomainBusy`-refusal on `obs(a)` for `a ≠ c`,
   and since ②′-(c) an *exact* match for what the code does (§4a-(c)).

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
the cascade composes both); the assembly went green in one arc; the last mile resolved cleanly
into "integrity: done; confidentiality: read-closure residual"; and the read-closure (§5f) then
discharged that residual in one more arc. **The true-diamond program A→D is complete at the model
level, in both directions** — Tiers A–C prove every invariant holds ∀-N; Tier D proves they
collectively imply *isolation*, integrity (nothing unauthorized *affects* a domain) *and*
confidentiality (a domain *learns* nothing unauthorized). The one remaining horizon is the **metal**
(M3+, ARM-first QEMU) — carrying these model guarantees onto hardware, an inherently new program
outside true-diamond, and the user's to open and time.

**The fork (the user's call).** Tiers A–C already make the safety **core** deductively proven ∀-N;
this spike shows Tier D's *"are we checking the right things"* capstone is reachable and its
property is *already validated on real code*. The remaining choice is whether to spend the few more
unwinding lemmas to make whole-system non-interference a **deductive theorem**, or to judge the
model-level diamond sufficiently established — the property is defined, validated exhaustively at
small size, and spiked ∀-N on two seams — and move to the metal (M3+). Either way, **these prove
the *model* (the pure brain); whether the *metal* enforces it is inherently M3+, outside this
program.**
