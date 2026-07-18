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

### x86 and ARM are co-equal targets

Just as the *personality* keeps the core ABI-agnostic northbound, the `hv-hal` fence keeps
it **architecture-agnostic southbound**. `hv-core` names no CPU architecture: its page
tables are a generic 4-level hierarchy (what x86-64 *and* AArch64 both use), and it reaches
hardware only through arch-neutral traits. The first `hv-metal` backend is **x86-64** (Intel
VMX / EPT, the LAPIC) — so the M3–M5 milestones below describe it — but an **AArch64**
backend (the ARM virtualization extensions at EL2, Stage-2 translation, the GIC) is an
**equally first-class goal**, not an afterthought: it is a second implementation of the same
`hv-hal` traits, and the diamonded brain above it does not change. This is a load-bearing
design constraint — the fence's trait surface stays free of any architecture-specific
concept, so the port is a new metal layer, never a rewrite.

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

Beyond sampling, `hv-sim::enumerate` does **bounded model checking**: for a tiny
configuration it breadth-first visits *every* reachable state and checks the
integrated invariant at each — a proof, not a sample, that no reachable state can
break it. CI runs shallow per-seam sweeps in seconds; the deep on-demand sweeps
(`cargo test --release -- --ignored`) have exhaustively cleared **millions** of
distinct states (grant↔page-type + page-table↔grant to depth 7 ≈ 742k states —
including cross-domain foreign *node* shares, not just leaves; the whole integrated
core to depth 5 ≈ 415k; event↔scheduler to depth 8 past the 1.5M cap) with zero
violations.

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
- **Event ↔ scheduler seam** *(landed)*: the second cross-subsystem invariant. The two
  oldest subsystems didn't talk — `evtchn::send` set a pending bit, and a vCPU that had
  called `SchedBlock` sat `Blocked`, so a signal to a sleeping vCPU's port was a **lost
  wakeup**, the classic bug class. They are now welded at the dispatch seam (subsystems
  stay pure and mutually ignorant): a `send`/`unmask` that makes a port *deliverable*
  (pending and unmasked) wakes the vCPU it notify-targets if that vCPU is `Blocked` —
  interdomain/unbound ports wake vCPU 0 (Xen's `notify_vcpu_id` default), VIRQ/IPI ports
  their bound vCPU. A *masked* port defers the wake to the later `unmask`. And a `block`
  is refused when a deliverable event already waits — Xen's `SCHEDOP_block` re-check —
  so a vCPU can't sleep *onto* work it already has. The safety invariant — **no
  deliverable event rests on a `Blocked` vCPU** — is debug-asserted after every dispatch,
  holds across 10k seeds (`run_seam` biases the stream to actually fire the wake, and
  observes it), and is fuzzed through the integrated target. Only the *scheduler* wakeup
  is the core's business; *injecting* the interrupt into an already-running vCPU stays
  the HAL's job, past the fence.
- **Domain teardown** *(landed)*: `HvCall::DomainDestroy` — the whole-system operation
  that welds all four subsystems and both seams at once. Tearing a domain down means
  closing its every port, offlining its every vCPU, unmapping its every grant map,
  revoking its every grant, and unpinning and freeing its every frame — an ordered
  sweep built entirely from the existing invariant-safe transitions, so it adds
  ordering, not new mutation. It is **atomic, all-or-nothing, refuse-if-busy**: one
  precondition gates everything — no *foreign* domain may hold a live grant map of one
  of the target's frames (the one thing teardown can't do is yank a page out from under
  another domain) — so it either refuses with a new `HvError::DomainBusy`, mutating
  nothing, or every step past the precondition succeeds by construction, leaving an
  empty but still-existent shell (domain slots are fixed-size and never removed; a peer
  left `Unbound` still names a domain that exists). No new standing invariant: a
  destroyed domain is verified by *postcondition* (nothing live points into it), riding
  atop the existing net, which already catches every teardown-ordering bug — a freed
  port with a live peer trips evtchn reciprocity, a freed on-CPU vCPU trips scheduler
  occupancy, a freed foreign-mapped frame trips the grant↔page-type seam, a deliverable
  event on an offlined vCPU trips lost-wakeup. Holds across 10k seeds (`run_destroy`
  builds domains up and tears them down mid-flight, reaching both the busy-refusal and
  clean-teardown paths) and is fuzzed through the integrated target.
- **Privilege model** *(landed)*: the authority floor beneath teardown. `DomainDestroy`
  had no authority check — *any* domain could destroy *any* other, a hole under every
  memory-isolation invariant. Introduce **authority** as the third axis after *ownership*
  (a domain acts on its own resources) and *consent* (grants authorize cross-domain
  memory): a per-domain privileged bit (domain 0 boots privileged, as Xen's dom0 does),
  and a gate checked *first* in `domain_destroy` — a domain may tear *itself* down, but
  destroying a peer requires being a control domain, else `HvError::Denied`, a true no-op.
  It lives at the dispatch seam because only the integrated core sees both the acting
  caller and the target. Authorization is a transition *guard*, not a state predicate (an
  unprivileged peer-destroy would leave a valid state — the point is it must never
  *happen*), so its correctness is "denies/allows correctly, and a denial mutates nothing":
  unit-tested, driven by `run_destroy` (which now predicts and checks the authority outcome
  and witnesses the denied path), and model-checked — the grant↔p2m depth-7 sweep still
  closes at exactly 1,143,997 states (the gate adds no reachable states and every denied
  destroy is invariant-preserving). A finer capability model (A may control specifically B)
  and delegable/mutable privilege are deferred; domain *creation* / ID reuse remains the
  natural next lifecycle step, now with an authority floor to stand on.
- **Multi-level page tables** *(landed)*: deepen `p2m` from a single page-table type into
  the full four-level hierarchy (Xen's `PGT_l1..l4`). A page-table type now carries its
  paging **level**, and the write-xor invariant generalizes to per-level exclusivity: a
  frame is referenced as at most one of {writable, L1, L2, L3, L4}. On top of that sits
  the genuinely new invariant — **hierarchical type-correctness**: `P2mLink`/`P2mUnlink`
  install and remove page-table *entries*, stored as explicit edges, and **every live
  entry must point exactly one level down** (an Lk table's entries reference L(k-1)
  tables; an L1's reference writable leaves). It holds by construction — a link takes a
  `get_type` reference on the child at the required level, so a mislevelled entry (a
  writable page where a table belongs, a table at the wrong level) is refused before any
  edge is recorded — and it is checked as a standing predicate (`MislevelledLink`) after
  every transition. A link also self-references its parent, so a table stays typed while
  it has any entry: it can't be freed, re-typed, or stranded under its children, and the
  child can't be re-typed or freed under its parent. Because a child always sits one level
  *below* its parent, the page-table graph is a DAG of depth ≤ 4 — no cycle is even
  representable. Holds across 10k seeds (`run_ptab` builds L4→L3→L2→L1→leaf trees and tears
  them down, reaching every level), is fuzzed through the integrated target, and folds
  into domain teardown (which unlinks a domain's whole tree before reclaiming its frames).
- **Cross-domain shared page tables** *(landed)*: a domain may now map a frame **another
  domain owns** into its own page table — the mechanism behind shared page tables and
  foreign memory mappings. Relaxing the ownership check quietly removes *isolation*, so the
  real content is a new checked invariant that replaces it: `p2m::link` now permits a
  foreign child (enforcing only the type discipline — the foreign frame is kept alive and
  write-locked, so its owner can neither free nor re-type it while the entry maps it), and
  the dispatch seam adds the **authorization** it is blind to. A cross-domain entry is
  allowed only when the frame's owner has granted it to the mapping domain
  (`grant::authorizes`) — Xen's grant-mapped foreign page — and, at this milestone, is
  restricted to `L1` leaves (sharing a page-table *node* was later lifted — see *Cross-domain
  shared page-table nodes* below). A grant can't be revoked while a
  foreign entry relies on it (the frame is in use), and the new cross-subsystem invariant
  **every cross-domain entry is backed by a live grant of matching permission**
  (`CrossViolation::UnauthorizedForeignLink`) is checked after every dispatch — the
  page-table↔grant join, the core's *third* cross-subsystem seam. It extends domain
  teardown too: a domain whose frame is foreign-mapped can't be destroyed
  (`has_foreign_link_into`, the page-table cousin of the foreign-grant-map precondition),
  while a mapper's own foreign entries are released by the existing `unlink_all`. Holds
  across 10k seeds (`run_foreign` grants, maps, unlinks, and revokes across the domain
  boundary, reaching the authorized, unauthorized, and revoke-blocked paths) and is fuzzed
  through the integrated target.
- **Read-only page-table leaves** *(landed)*: an `L1` leaf now carries the paging
  read/write bit, which sharpens the central exclusivity rule from "no reference coexists
  with a page-table type" to its exact content: **write-xor-pagetable**. A *writable* leaf
  holds a `Writable` type reference on its child (so it can never also be a page table); a
  *read-only* leaf holds only a bare existence reference — a reader is type-agnostic,
  exactly as a read-only grant map already is — so it may point at **any** allocated frame,
  including a live page table. That is the *linear-map* case a guest reading its own page
  tables depends on, and it is safe precisely because neither path can write the frame. The
  seam authorizes a foreign leaf at its *matching* permission (a read-write grant for a
  writable entry, any grant for a read-only one), refining `UnauthorizedForeignLink`. The
  read-only transition is model-checked exhaustively (the grant↔p2m sweep closes at depth 7
  over ≈1.14M states, zero violations, with read-only-onto-page-table reached), witnessed
  by the seeded `run_ptab`/`run_foreign` drivers, and fuzzed. Shared page-table *nodes*
  (foreign interior entries, not just leaves) landed later — see *Cross-domain shared
  page-table nodes* below.
- **Domain lifecycle / creation** *(landed)*: close the lifecycle loop. Teardown existed,
  but there was no *creation*, and every domain slot implicitly existed and accepted
  operations from birth — there was no "doesn't exist yet" state. Model it explicitly: a
  `DomainLife { Dead, Live }` per slot. **Domain 0 boots `Live`+privileged** (the
  primordial control domain); **every other slot boots `Dead`**. `HvCall::DomainCreate {
  target, privileged }` is `Dead`→`Live`, privileged-caller-only, and stamps the new
  domain's authority; `DomainDestroy` is now `Live`→`Dead` and clears privilege on death.
  The load-bearing change is a **caller-liveness gate**: every hypercall requires a `Live`
  caller, checked once centrally — which is what turns "a `Dead` domain owns nothing" from
  teardown's one-shot postcondition into a *standing* invariant (a slot that can issue no
  hypercall can never acquire a resource to hold), and makes target-liveness fall out for
  free (a `Dead` domain offers no grant and owns no frame, so any op naming one already
  fails naturally). Two new standing invariants join the cross-check family:
  **`DeadDomainNotClean`** (every `Dead` slot is an empty shell across all four subsystems —
  the graduated postcondition) and **`PrivilegedDeadDomain`** (privilege implies `Live`).
  The second is the point: privilege is now **stateful and constrained**, so it is finally
  *invariant-bearing* rather than a bare guard — the sole transition that confers privilege
  is `DomainCreate`, itself privilege-gated, so **no domain can self-elevate**, a provenance
  the model checker confirms by finding no reachable self-elevated state. New errors
  `NotAlive` / `AlreadyAlive`; authority reuses `Denied`. dom0 may be destroyed with no
  special case (minimal-sound — it just strands the system). Verified end to end: the
  seeded `run_destroy` now cycles domains `Dead`→`Live`→`Dead`→`Live` and predicts every
  create/destroy outcome; a dedicated lifecycle sweep model-checks the standing invariants
  exhaustively (closes complete at depth 12 over 10,178 states); and the whole thing is
  fuzzed. The grant↔p2m depth-7 sweep re-measures at **715,164** states (down from ≈1.14M:
  the liveness gate and creation reshaped the reachable set — a second domain must now be
  *created* before it can act, so the old boot-time two-domain states sit behind a creation
  edge), the integrated-core sweep at 382,008 — all clean, zero violations. Finer/delegable
  privilege (a capability model, mutable privilege) and domain-ID reuse policy stay
  deferred; the lifecycle now has both a birth and a death to build them on.
- **Finer / delegable privilege** *(landed)*: refine the coarse authority bit into a real
  capability model, now that the lifecycle made authority stateful. One `privileged` bit
  had bundled two powers — "may create domains" *and* "may destroy any domain" — so split
  it. `may_create` (the honest residue, renamed from `privileged`, its invariant
  `PrivilegedDeadDomain` → `DeadDomainMayCreate`) is a global capability gating only
  creation, with the same provenance (only a `may_create` domain confers it, so none
  self-elevates). **`controls[H][T]`** is the new *per-target* authority: H may destroy T
  *specifically* — a capability over one named domain, not a blanket privilege. It is
  **rooted in creation** (creating T grants the creator `controls[creator][T]`) and
  **delegable** (`ControlGrant`/`ControlRevoke` hand it to, or take it from, another
  domain). Pure **least-privilege**: no implicit transitivity, so a domain controls exactly
  what it created or was delegated — dom0 holds *no* blanket power over a grandchild it did
  not build. Destroy is gated on `controls[caller][target]` (or self), never a global bit;
  a nice consequence is that a `Dead` domain has no controller, so destroying one is
  `Denied`, indistinguishable from a live-but-uncontrolled peer (no liveness leak). New
  standing invariant **`ControlEdgeDeadEndpoint`** — every control edge relates two `Live`
  domains — and teardown clears every edge into *and* out of a domain, so **no capability
  outlives the domain it named**. This is authority made fully invariant-bearing
  (design-lessons #9/#10 carried to their conclusion): stateful, per-target, delegable, and
  constrained. Flat delegation for now — any controller may delegate or revoke any edge,
  sound because edges only ever trace back to a creation root; hierarchical (chain-restricted)
  revocation is the deferred refinement. Model-checked exhaustively over every reachable edge
  configuration: the lifecycle+delegation sweep closes complete at depth 12 (18,422 states),
  the integrated core at depth 5 (415,417), grant↔p2m at depth 7 (738,897) — all zero
  violations, with `run_destroy` and the fuzzer exercising create/destroy/delegate/revoke
  and predicting every outcome. A domain **capability** delegable to specific peers is exactly
  the toolstack-domain / driver-domain disaggregation Xen's XSM/Flask does coarsely — here it
  is a checked invariant.
- **Cross-domain shared page-table nodes** *(landed)*: lift cross-domain sharing from
  leaf-only to a foreign **node** — an `Lk` table (`k >= 2`) pointing at another domain's
  `L(k-1)` table, sharing a whole page-table *subtree* rather than a single data page. This
  is the mechanism behind a real shared address space. The lift is one deleted line: the
  only thing forcing leaves was `current_type(parent) == PageTable(L1)` for a foreign child
  in `p2m_link`; dropping it lets a foreign child sit at any level, authorized by the
  *unchanged, uniform* `grant::authorizes(owner, caller, child, writable)` — a read-write
  grant for a writable entry, any grant for a read-only one — whether the child is a data
  page or a table node (design-lesson #6/#8: relaxing a check is sound only because its
  replacement invariant already covers the relaxation). **Transitive consent** is the model
  and it *falls out* of the existing seam rather than being built: `UnauthorizedForeignLink`
  only fires on edges whose parent and child differ in owner, and every edge *inside* the
  owner's shared subtree is same-owner, so one grant of the node frame authorizes the
  caller's walk into the entire subtree beneath — the caller holds, and needs, no grants of
  the leaf frames. On an interior entry `writable` is the traversal read/write bit the MMU
  ANDs down the walk (past the fence): it gates the grant permission required but never
  yields a writable *type* on the node (a node is always typed as a page table), so a
  read-only node grant can never produce write access to the leaves beneath. Three
  guarantees hold for free, confirmed not assumed: **acyclicity** (every edge, foreign
  included, strictly decreases level, so the cross-domain graph stays a DAG of depth <= 4 —
  no cycle representable); **teardown & revoke-block** (both key on the boundary edge, so
  `has_foreign_link_into`/`is_foreign_linked_by` already refuse tearing down a domain whose
  node a peer shares, or revoking the grant under a live share); and the **replacement
  invariant** itself, which already scanned every edge at every level. Model-checked
  exhaustively — the grant<->p2m depth-7 sweep now reaches a foreign interior node share and
  everything under it, re-measured at **741,777** states (up from 738,897), closed complete,
  zero violations — witnessed by the seeded `run_foreign` (now sharing and tearing down
  cross-domain subtrees, with a `node_links` reachability witness) across 10k seeds, and
  fuzzed through the integrated target.
- **Hierarchical control revocation** *(landed)*: close the flat-delegation wart. The
  capability model shipped `controls` as a bare boolean matrix, so *any* controller could
  revoke *any* edge — its own delegator's included. Sound (revocation only removes authority)
  but a policy wart. Fix it by recording **provenance**: each cell becomes a `Control` —
  `Absent | Root | Via(D)` — so each target's column is a **delegation tree** rooted at its
  creator (`Root`, stamped at `DomainCreate`), every delegated edge (`Via(D)`, stamped at
  `ControlGrant`) recording the delegator `D` that handed it out. `ControlRevoke` becomes
  **chain-restricted and cascading**: a caller may revoke `from` only *within the subtree it
  roots* — `from == caller` (renounce) or a domain the caller delegated to transitively — never
  upward at a delegator, sibling, or the `Root` from below (Denied); and removing an edge
  cascades its whole delegated subtree away, so nothing is orphaned. `DomainDestroy` folds
  **delegator-death** into the same cascade — a torn-down delegator's `Via` edges (where it is
  neither endpoint) are swept — via one shared fixpoint. **Acyclicity comes from the
  transition, not an ordering** (there is no natural order on domains, unlike page-table
  levels): a `Via` edge only ever attaches a *fresh* leaf beneath a present delegator, so no
  interleaving can close a cycle — which is exactly why `ControlGrant` must be idempotent and
  **provenance-preserving** (re-parenting an existing controller is the one move that could
  forge a cycle). This is the diamond move the capability arc set up (design-lesson #11e): the
  stored provenance **upgrades "every edge traces to a creation root" from a by-construction
  guard property into a checked state invariant**, `ControlEdgeOrphaned` — walking any present
  edge's provenance must terminate at a `Root` within `domain_count` steps, catching both an
  orphan (a `Via` whose delegator's cell went `Absent`) and a cycle (no `Root` in bound). It
  sits *beside* `ControlEdgeDeadEndpoint` (endpoint liveness); neither subsumes the other.
  Model-checked exhaustively over a dedicated four-domain create/destroy/delegate world — the
  smallest that can form a depth-2 delegation chain (a two-domain world cannot even represent a
  `Via` edge) — closing complete at depth 8 with **30,992 states, zero violations**; the
  `state_key` now fingerprints provenance, not mere presence, so no two distinct trees merge.
  Witnessed by `run_destroy` (bumped to four domains) across 10k seeds, which predicts every
  revoke outcome via an independent subtree re-derivation and reaches both a **chain-restricted
  denial** (the wart-closing refusal) and a genuine **cascade** (a revoke that removed a whole
  subtree). A delegatee that can no longer strip its delegator, while an ancestor still can and
  it cascades, is the disaggregated-toolstack authority Xen's XSM does coarsely — here a checked
  invariant.
- **Superpages** *(landed)*: a page-table entry may now be a **leaf at any level**, not
  only under an `L1`. A leaf terminates the walk and maps an ordinary `Writable` page; above
  `L1` it is a **superpage** — a 2 MiB page mapped directly by an `L2` entry, a 1 GiB page by
  an `L3` — with its size carried by the parent entry's level, no leaf type of its own (real
  hardware's large pages, and how EPT/Stage-2 map guest RAM). This lands *between* the two
  prior page-table arcs, and naming which is the point. Unlike the *nodes* arc it is **not** a
  one-line relaxation: leaf-vs-interior was inferred from the parent level (`level == L1`),
  and a superpage makes an `L2` entry ambiguous — a **read-only** superpage in particular
  leaves its child untyped, so an `L2`→untyped-child edge is a legitimate 2 MiB leaf *or* a
  corrupt interior edge, and only stored state tells them apart. So the entry records a
  `leaf` bit — real hardware's page-size / `PS` bit — **new stored structure** (design-lesson
  #5), modeled with the existing bool idiom like `writable`, not a new `PageType`
  (design-lesson #8). But unlike the *revocation* arc it earns **no new named invariant**: the
  existing `MislevelledLink` hierarchy invariant *generalizes* to read the bit (a leaf's child
  is a valid leaf target — `Writable`-typed if writable, merely allocated if read-only; an
  interior entry's child is the level below), so the honest result is *new structure, an
  existing invariant generalized, zero new seams*. `ChildRef`/`entry_child_ref` make `link`
  (which reference to take), `unlink` (which to give back), and the invariant (which type the
  child must be) all derive from one place, so they cannot drift. Three guarantees hold **for
  free**, confirming design-lesson #12 a third time: **write-xor-pagetable** binds at superpage
  size unchanged (a writable 2 MiB leaf pins its child `Writable`, so it can never also be a
  page table); the **foreign-link seam** — `UnauthorizedForeignLink`, already a scan over
  *every* edge — authorizes a shared 2 MiB leaf off the one grant a shared 4 KiB leaf needs,
  and teardown/revoke-block key on the boundary edge, level- and shape-agnostic; and
  **acyclicity** is untouched because a leaf is *terminal* (no page-table child to descend).
  Frame contiguity/alignment of the 512 sub-frames a real superpage spans is deliberately
  **abstracted out** — a leaf pins one `Mfn`, and the accounting is identical whether it
  stands for 4 KiB or 2 MiB; contiguity is an MMU/allocator concern for `hv-metal`, not a
  brain invariant. Model-checked exhaustively: the enumerator now drives both entry shapes
  (required to keep its interior coverage once `leaf` is explicit) and `state_key` fingerprints
  `leaf` so a superpage and a small-page mapping of the same frame never merge (design-lesson
  #7); the grant<->p2m depth-7 sweep — now building 2 MiB superpage leaves as well as small
  pages and node shares — re-measured at **852,085** states (up from 741,777), closed complete,
  zero violations (lifecycle depth-12 likewise grew 18,422 → 45,920). Witnessed by the seeded
  `run_ptab` (a `superpages` reachability witness) and `run_foreign` (a foreign 2 MiB leaf
  shared and authorized by one grant, `superpage_links`) across the seed space, and fuzzed
  through the integrated target. No soundness bug found.
- **Domain-ID reuse** *(landed)*: a `DomId` is an index into a fixed slot table, and
  `DomainCreate` reuses a `Dead` slot — so the same id names different domains over time. The
  lifecycle arc proved a `Dead` slot is a clean shell *outbound* (owns and offers nothing); this
  arc closes the *inbound* direction. Two references survived teardown naming a slot by bare id,
  so a reborn tenant silently inherited them — a **different security principal served by a
  reference made for its predecessor**: a grant `{grantor:A, grantee:D}` outlived `D`, so a
  reborn `D'` could map it and reach `A`'s frame (a confused deputy across the reuse boundary);
  and `close_all(D)` returned each interdomain peer to `Unbound { remote: D }`, so a reborn `D'`
  could bind it, inheriting a channel the peer opened for `D`. A bare id is a stable identity
  only if no reference to a past incarnation survives into the next. **Rather than a per-slot
  generation counter** (Xen's approach): an unbounded incarnation would break the enumerator's
  finite-state BFS — create/destroy/recreate would split every rebirth into a fresh state and the
  search would never close — and it leaves inert dangling references around, against this brain's
  clean-by-construction grain. Instead the lifecycle loop is closed on the *inbound* direction,
  over **existing state, no new stored structure**: a **mint gate** (`reject_dead_target`) refuses
  `EvtchnAllocUnbound`/`GrantAccess` naming a non-`Live` target (`NotAlive`), so no inbound
  reference to a `Dead` slot is ever created; and a **teardown sweep** clears every *other*
  domain's `Unbound { remote: target }` port (`clear_unbound_into`) and every inbound grant
  `{grantee: target}` (`revoke_grants_to`), so none survives the domain it named. The new standing
  invariant `DeadDomainReferenced` is the **inbound complement of `DeadDomainNotClean`**: together
  they say a `Dead` slot holds nothing *and* nothing points at it — a truly isolated shell, so a
  reborn domain inherits nothing. (A live `Interdomain` port naming a `Dead` slot needs no check:
  it would already break event-channel reciprocity, since a `Dead` domain's ports are all `Free`.)
  Naming which design-lesson shape this is *is* the point: unlike the prior three page-table arcs
  it is a **new checked invariant with no new stored structure** — the fourth corner of the
  structure×invariant matrix (nodes = neither, revocation = both, superpages = structure only),
  and a lifecycle-closure in the spirit of the create/destroy arc, carried to the inbound
  direction. Model-checked exhaustively by a new `reuse_cfg` (grants + interdomain channels +
  create + destroy — the smallest world that references a slot and reuses it, which the lifecycle
  sweep could not represent): closed clean shallow, no violation at the deep 1.5M-state cap. The
  coverage is not vacuous — with the mint gate and sweep removed, `reuse_cfg` surfaces a
  counterexample at depth 1 (`EvtchnAllocUnbound { remote: 1 }` naming the boot-`Dead` slot 1).
  `state_key` fingerprints liveness and both reference kinds but deliberately carries **no
  incarnation**, so a slot cycled `Live→Dead→Live` merges with one never destroyed — which keeps
  the reachable set finite, and `DeadDomainReferenced` is what makes that merge sound. Witnessed
  by two seeded `hv-core` cases (a reborn domain inheriting neither a stale grant nor a stale
  channel) and the `run_destroy` seed sweep — which cycles `Dead→Live→Dead→Live` with inbound
  references live and asserts the invariant every step — and fuzzed through the integrated target.
  No soundness bug found.
- **vCPU affinity** *(landed)*: the scheduler had exactly **one** invariant — pCPU exclusivity —
  and no notion of *where* a vCPU is allowed to run: a `Runnable` vCPU could be dispatched onto
  **any** idle pCPU. This gives the previously invariant-light scheduler its **second safety
  invariant**. Each vCPU carries a **hard-affinity mask** (real hardware's cpumask, Xen's
  `cpu_hard_affinity`) — the set of pCPUs it may run on — defaulting to *all* pCPUs so existing
  "run anywhere" behaviour is unchanged until narrowed. A new `SchedSetAffinity` op sets it, and
  `SchedRun` is **guarded**: a dispatch onto a pCPU outside the mask is refused (`NotAffine`). The
  new standing invariant is **"a `Running` vCPU is always on a pCPU in its affinity set"**
  (`RunningOffAffinity`); only two transitions can violate it (dispatch, and narrowing affinity),
  and both are guarded, so it holds by construction. Three design calls define the shape: **(1)
  a per-target control operation** — affinity is a resource-management decision (which pCPUs a
  domain may use), so setting it is Xen's `XEN_DOMCTL_setvcpuaffinity` domctl: a domain may affine
  its *own* vCPUs, but a *peer's* requires the caller **control** that peer
  (`controls[caller][target]`), the same per-target authority gate `DomainDestroy` uses — the third
  isolation axis (after ownership and consent) applied to scheduling. (It shipped self-service
  first, the sound core, then had the control axis layered on; the authority check lives at the
  seam, so the scheduler subsystem stays authority-agnostic.) This is a transition *guard*, not a
  new state invariant, and the exhaustive sweep confirms it: adding the gate left the
  reachable-state count **exactly unchanged** (a controller reaches only affinity states the domain
  could set itself; a denied peer op is a no-op) — the same signature the `DomainDestroy` gate
  showed. **(2) Refuse, don't force-migrate** —
  setting an affinity that excludes the pCPU a vCPU is *currently* running on is refused (a no-op),
  not resolved by a forced migration; the brain's gating-precondition style over side-effects (as
  teardown refuses-if-busy), which keeps the invariant true by construction and `set_affinity` a
  pure mask write. **(3) Reset on offline** — because affinity is *behaviourally live* (it gates
  `run`, unlike `runtime`, which gates nothing and is dropped from the state fingerprint), `offline`
  resets it to the all-pCPUs default, so a re-admitted vCPU — or one **reborn in a reused domain
  slot** — inherits no stale scheduling constraint. That is a deliberate departure from Xen (which
  preserves affinity across offline), made for exactly the reason the domain-ID-reuse arc chose
  eager cleanup over a generation counter: a reborn domain must behave identically to a fresh one,
  and a behaviourally-live field must not leak across the lifecycle. An **empty** mask (run nowhere)
  is deliberately allowed — an unschedulable vCPU is a *liveness*/policy concern, not a safety one,
  the same dividing line that keeps fairness out of this module. Model-checked exhaustively by a new
  `affinity_cfg` over **two** pCPUs (so a mask can genuinely exclude one), driving every mask across
  every placement: closed clean shallow, and coverage proven non-vacuous — with the run-guard
  removed the sweep surfaces `RunningOffAffinity` immediately. `state_key` fingerprints the mask
  (behaviourally live — design-lesson #7). Witnessed by six `hv-core` cases and the seeded
  `run_sched`/`run_hypervisor` mirrors, and fuzzed through the scheduler and integrated targets with
  a fuzzed mask so off-affinity dispatches are attempted directly. No soundness bug found.
- **Adversarial audit & verification-depth consolidation** *(landed)*: seven feature arcs deep,
  the obvious backlog thin and zero soundness bugs ever found, the discipline says stop *adding*
  and start *auditing*. This arc is not a feature — it is a systematic attempt to **break** the
  whole (now large) invariant set on paper, then confirm the code and the model-checker already
  prevent it, and to consolidate where the verification was a *lower bound* rather than a *theorem*.
  The audited surface is **28 standing state invariants** — event channels (4: interdomain
  reciprocity, no-signal-on-`Free`, VIRQ uniqueness, no ghost peer), grant tables (5: refcount
  coherence, read-only integrity, grantee identity, `writable_maps ≤ maps`, no dangling map), the
  scheduler (5: pCPU-exclusivity reciprocity from both sides + no ghost occupant, and `Running`
  on-affinity), page-type accounting (5: owner integrity, write-xor-pagetable, typed `≤` refs,
  pinned `⇒` page-typed, level-correct links), and the **nine cross-subsystem seam invariants**
  (unbacked/misowned grant map, lost wakeup, unauthorized foreign link, a `Dead` slot
  clean/unreferenced/`may_create`-free, a control edge live-endpointed/rooted-acyclic) — plus the
  credit account's conservation, and the **~10 transition *guards*** proven differently (a guard is
  a no-op-on-refusal, not a state predicate — design-lesson #9): the caller-liveness gate, the
  `reject_dead_target` mint gate, the global `may_create` and per-target `controls` authority
  gates, the revoke chain-restriction, the `StaleGrant`/`Unauthorized`/`DomainBusy` seam checks,
  the `grant_end_access` foreign-link block, and the `sched_block` deliverable re-check. Four
  passes. **(1) Gap hunt** — for every invariant, enumerate every transition that could move the
  system toward violating it (design-lesson #3) and confirm each is guarded or maintained by
  construction, hunting specifically for a falsification path *nothing* guards. Every threatening
  edge is covered; the subtle ones re-derived and reconfirmed — the `grant_end_access` /
  `revoke_grants_to` **ordering** (a foreign page-table link into `target`'s frame blocks teardown
  up front via `has_foreign_link_into`, and inbound grants are revoked only *after* the p2m
  teardown drops `target`'s own outward links, so no revoke ever strands a live foreign entry);
  the `maps_over_frame` summation (sound because two grantors with live maps over one frame is
  unreachable — the misowned check would fire first, and a live map pins ownership); the cascade
  fixpoint (`sweep_orphaned_control_edges` removes exactly a just-orphaned subtree, and the
  provenance walk's `steps > n` bound cannot false-positive on a legitimate depth-`n` chain).
  **(2) Redundancy / subsumption** — no invariant is dead or subsumed. Two deliberate
  conservatisms confirmed *safe, not unsound*: `grant_end_access` blocks a revoke on *any* foreign
  link by the grantee, not only the one this grant authorizes (a liveness wart, never a hole); and
  the `L1`/`L2`-only pin universe is *isomorphic* to `L3`/`L4` (the level logic is a symmetric
  match — higher levels add no reachable code path). **(3) Cross-invariant interaction** — every
  feature *pair* is either model-checked together or *provably decomposable*: vCPU affinity is
  orthogonal to grant/p2m/evtchn (no cross-invariant reads the affinity mask, and no non-scheduler
  transition touches scheduler state — so the siloed two-pCPU `affinity_cfg` is complete), and a
  *delegated* `Via` control edge drives the **identical** grant/evtchn teardown a creation `Root`
  edge does (the cascade touches only the control matrix), so the 2-domain `all_cfg` and the
  4-domain `delegation_cfg` cover it without an intractable four-domain-everything sweep. The
  scheduling *policy* layer is out of scope by construction — it enacts only through the public,
  invariant-checked transitions, so the same safety net covers it (its fuzz target re-asserts pCPU
  exclusivity). **(4) Depth consolidation** — the one place verification was a lower bound: the
  event↔scheduler and domain-ID-reuse deep sweeps *truncated* at the 1.5M-state cap. Characterizing
  their closing depth showed both **close exhaustively at depth 7** (≈2.12M and ≈5.66M states), so
  both were **upgraded from truncated lower bounds to complete theorems** (depth 7, raised cap) —
  and because BFS visits shallower depths first, each closure *strictly subsumes* the earlier
  truncated run (which had not even finished the depth-≤7 states) while adding completeness. **Every
  deep sweep now closes.** **Outcome: no soundness bug, and none expected — the by-construction
  design holds across all 28 invariants × every threatening transition.** That is the valid,
  valuable result the audit was for: it answers the direction's own load-bearing question — *how
  close is the pure brain to "can't diamond anymore"?* — and the honest read is **very close**. The
  remaining headroom is not soundness holes but (a) *policy* refinement with no safety content
  (event-vCPU steering, richer scheduling), (b) *breadth* the fence defers to M3+ (wider cpumasks,
  512-entry tables, the real ABIs), and (c) ever-deeper sweeps with diminishing marginal
  confidence. The safety core is essentially complete; what remains is hardware.
- **M3**: `hv-metal` boots on real hardware to a serial "hello" and enters VMX root
  mode. The first `unsafe`, weeks in rather than day one. (x86-64 is the first backend; an
  AArch64 `hv-metal` — EL2, Stage-2 translation, the GIC — is a co-equal target behind the
  same `hv-hal` fence, per *x86 and ARM are co-equal targets* above.)
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
