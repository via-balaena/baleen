# M5 Arc 6a — the refinement learns SPAN

**Status:** done. `hv-core` / `hv-hal` untouched.

The model has had superpages since design-lesson #14 — a leaf hanging off a table one level up from
the bottom, invariant-bearing and proven. The metal's emitter **flattened every one of them into a
4 KiB page descriptor**, mapping 1/512th of what the model authorized. Audit #2 named this ("superpage
size abstracted") and it was *sound* — an under-map fails closed — but it capped the proven Stage-2
path at 512 frames × 4 KiB = **2 MiB**, which is why the real-Linux capstone had to run behind a
separate, unproven identity mapper (`linux.rs::build_stage2`) instead of the proven emitter.

This arc carries the span through, end to end: neutral layer, encoder, both provers, and the metal.

---

## 1. The audit, before any code

### A trap: the two layers name levels in opposite directions

- `hv_core::PtLevel` counts **up** from the bottom — `L1`'s entries map ordinary pages.
- ARM / `hv-s2` counts **down** from the root — `L3`'s entries map 4 KiB pages.

Order-reversing. Passing a `level` across the `hv-s2` seam would have been a silent inversion waiting
for whoever adds a third level. **So the level never crosses.** What is architecture-neutral is the
**span** — how much memory one leaf covers — and turning a span into a descriptor level is `arm64`'s
job alone. `hv-s2` has to stay neutral enough to serve x86 EPT (the standing broad/ARM-first
constraint). `span_of_table` is the single translation point; `hv-core` is untouched, the span being
recovered through an oracle parameter in the Arc-3 style.

### Two maps, not one map of `(Perm, Span)`

A flat `Mfn`-indexed array **per span** preserves what the ∀-N proof rests on: each map is a total
function over its index space, so intra-map overlap is not *representable*. One mixed index space
would have made overlap representable and turned a structural fact into a proof obligation.

### The new safety property

With one span, distinct leaves **could not** overlap in IPA. With two, they can, so non-overlap is
now pinned by `Layout::validate`: three-way pairwise-distinct `L1` entries and disjoint windows in
**both** address spaces — structurally (disjoint windows), not re-checked per leaf. `sup_frames`
makes validate check the *backed* span, so a window larger than its backing cannot pass and then
alias something real.

This is the #12-vs-#13 question answered honestly: the arc does **not** merely generalize an existing
invariant. Mixed spans introduce a hazard uniform addressing made unrepresentable.

---

## 2. Two hazards the model permits — both reached by the enumerator in a handful of hypercalls

Not hypothetical, and not found by reading:

- **`SpanConflict`** (6 hypercalls): one frame as a leaf under *both* an `L1` and an `L2` table. It
  would need two machine-frame backings (each span has its own window), which the `Mfn` → host-PA
  function cannot represent. Nothing in `hv-core` forbids it — `MislevelledLink` constrains only
  *interior* children, so a leaf's child is `Writable`-or-untyped at any level.
- **`UnsupportedSpan`** (3 hypercalls): a leaf at a level the emitter does not encode.

### And that exposed a labelling error of mine

I first folded both into `Violation` — which made the enumerator report **perfectly legal model
states as isolation failures**; four tests went red saying so. A `Violation` means *the emitted table
would be wrong*. These mean *this state is outside the refinement's domain*. So `check_all` returns
`Verdict::{Violated, OutOfDomain}`, only `Violated` is a counterexample, and the domain limit became a
**measured number** (§4). The metal still fails loudly on both, which is correct *there*: it cannot
represent the state, so it must stop rather than emit a wrong-*sized* map.

---

## 3. What shipped

**Encoder.** `Layout` gains its own super window (`l2_sup_pa`, `sup_ipa_base`, `sup_pa_base`,
`sup_frames`); `Tables`/`TablesRef` gain `l2_sup`. `encode` writes 2 MiB `BLOCK` leaves into their own
`L2`, indexed by **the block's own L2 slot derived from its IPA** — not by `m` — so the window's base
offset cannot silently relocate a mapping. `super_size` is **derived** from `frame_size`, so the two
cannot drift (#14c).

**Data blocks are execute-never, with their own constants.** The only executable mapping this emitter
writes is the shared guest image. Reusing `BLOCK_ROX` would have handed a guest an execute surface
512× the size of a page.

**Both provers carry the span axis, from opposite ends.**

- **Kani**: `World` gained a per-frame *symbolic* span, so `emitted_leaf_map_is_always_authorized` is
  proven over every assignment of base/super spans to parents — including assignments that put one
  child under tables of both spans. 620 checks, 0 failed; **15/15 harnesses** across the suite.
- **Verus**: fixed by **generalizing, not duplicating**. `selected` gained a free
  `span_sel: spec_fn(Mfn) -> bool` and T is proven for an *arbitrary* span filter, so the production
  loop writing `base` is the theorem at one instantiation, `sup` at another, and a future third span
  needs no new proof. Sound because **authorization is span-independent**: the span decides *which*
  map, never *whether* a frame is authorized. **12 files, 61 verified, 0 errors.**

**Metal.** A 2 MiB `__guest_sup_*` NOLOAD window (one super frame — enough to exercise the path
without reserving the 1 GiB a full super table spans), its own `L1` entry, and a fifth table per
Stage-2 set. The phase-1 model config builds a real superpage, `verify_encoding` runs against a
**non-empty** super table on every CI boot, and **the guest probes it**: a store and load through the
2 MiB block, gated into the isolation matrix so the matrix marker cannot print if the superpage did
not round-trip. `SUP_IPA_HI` is bound to `stage2::SUP_IPA_BASE` by a `const _` assert.

boot-test **135 → 138 checks**, both feature configs.

---

## 4. The refinement's domain, measured — and a metric that was wrong first

`refinement_domain_coverage_is_measured` reports, on the hierarchy-heavy config:

> **2,520 of 9,448 reachable states (26.7%) are OUT OF DOMAIN.**

**Read that number with its caveat.** `deep_hierarchy_cfg` deliberately builds `L1`–`L4` tables, so it
is the config most likely to produce leaves at assorted levels; it is an upper bound, not a typical
one. What it establishes is that the domain limit is *substantial and real*, not a rounding error —
which is exactly why it must be a number rather than a sentence.

**The first version of this metric was wrong and reported 908.5%.** The check runs once per generated
transition and states are deduped afterwards, so a naive counter measures *checks*, not *states*. A
coverage figure has to be states-over-states or it is not a fraction of anything. Fixed to a set of
distinct state keys. Recording it because a metric that cannot exceed 100% would have hidden the bug.

---

## 5. Mutation table

| # | Mutation | Result |
|---|---|---|
| 1 | Emitter does not write the super block | **CAUGHT** — the guest's probe fails, isolation matrix marker gone |
| 2 | Flatten the superpage into a 4 KiB page (**the pre-arc behaviour**) | **CAUGHT** — translation breaks |
| 3 | Drop `XN` from data blocks (a data superpage becomes executable) | **CAUGHT** by `verify_encoding`'s decoder on the real tables |

---

## 6. Residual

1. **`linux.rs::build_stage2` still exists.** Arc 6a makes the proven emitter *capable* of hosting a
   real guest; it does not rehost it. Until 6b, the only real Linux guest still runs behind an
   emitter no proof touches — the gap that motivated this arc is narrowed, **not closed**.
2. **One backed super frame.** The metal reserves 2 MiB, so the super path is exercised but not at
   scale; a real guest needs the window sized up (NOLOAD, so it costs image nothing).
3. **1 GiB spans (a model `L3` leaf) are `UnsupportedSpan`** — rejected loudly, not emitted.
4. **`SpanConflict` is rejected, not resolved.** The model can reach it and the metal halts. Whether
   `hv-core` *should* forbid a frame being a leaf at two levels is a model question this arc
   deliberately did not open.
5. **The 26.7% figure is one config.** A per-config coverage table would be more useful than a single
   number, and does not exist.
6. **`super_size` assumes the base-level table is fully populated** (512 entries), which is true at a
   4 KiB granule on both targets but is an architecture fact, not a proven one.
