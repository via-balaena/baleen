# The device-path composition — the arc's headline sentence, as one theorem

*The SMMU arc's last rung with machine-checkable content, and the one that found itself. Rung 1*
*(#91) closed the pre-enable DMA window; rung 2 (#92) made the answer to an unbound bus master*
***no***; *rung 3 (#93) confined a bound one to a domain's proven `p2m`; rung 4a (#94) put the*
*device→domain relation in `hv-core`; rung 4b (#95) made the stream table a proven refinement of*
*that relation. After 4b the arc looked exhausted. It was not: **nothing composed the links**.*

---

## 0. THE CEILING — stated before any of it was written

This rung **narrows the glue; it does not remove it.** Three things stay true afterwards and are
recorded here first so the rest of the document cannot quietly outrun them:

1. **`hv-metal` is not a Kani target.** "The metal hands the emitter and the derivation the *same*
   `Layout`, and that `Layout` describes the storage `encode` actually wrote into" stays a
   construction argument — one line of `hv-metal` (`l1_pa: tables.l1.0.as_ptr() as u64`) that no
   proof reads. What this rung does is make it the **only** such line on the device path: everything
   downstream of it becomes a function of that one value.
2. **Composing functional refinements is mathematically routine.** The risk in a composition lives
   in the links, and the links here are proven. A composition theorem is therefore *expected* to go
   green on the first try, and going green is nearly no evidence at all.
3. **So the value is in what writing it out longhand FINDS**, which is the part this repository has
   a record on (every ②′ rung found a real defect; GAP-C forced four modelling corrections; rung 3's
   ∀-regime proof caught a real modelling error). If it had found nothing, the honest report was
   "this reads thin" and a move to the next item — that was the standing instruction.

**It did not read thin.** §2 is what writing it out found: four preconditions `encode` has always
had, none of them stated, none of them checked, every one of them silently mis-mapping rather than
failing. §5 records what is still *not* claimed.

## 1. The finding, which is the whole reason the rung exists

All 59 harnesses were listed and the device path's three links were each found proven —
**separately**:

| link | what proves it |
|---|---|
| assignment → STE | `the_derived_table_binds_exactly_the_assigned_streams` (rung 4b) |
| STE ↔ table + VMID + regime | `a_bound_stream_names_exactly_the_domain_it_was_given`, `the_vttbr_seam_recovers_the_table_and_the_vmid`, `the_device_and_the_cpu_walk_under_one_regime` (rung 3) |
| `p2m` → leaf map → descriptor bits | `emitted_leaf_map_is_always_authorized`, `an_unauthorized_frame_is_never_mapped`, `encode_leaf_descriptors_follow_the_seam` (the Stage-2 programme + GAP-A) |

**And nothing composed them.** So the sentence the whole arc exists to justify —

> a device assigned to `d` reaches exactly the frames `d`'s `p2m` authorizes, at exactly the
> emitter's permissions, and nothing else

— was a **citation across three artifacts**. `docs/SMMU-TRANSLATION.md` §1 even says the refinement
"carries over verbatim" and §3 that rung 3 "re-proves none of it": that is the citation doing the
work. That is GAP-C's shape, and design-lesson #78 names it — *when a new obligation can be
discharged by citing an existing one, that is the moment to write it out longhand.*

**Method note, because it generalizes.** This rung was found neither by interrogating the ledger
(⑥) nor by diffing two artifacts that should agree (⑦), but by a third move: **write the arc's
headline claim as one sentence and ask which single artifact checks it.** If the answer is "these
three, together", the composition is the rung.

## 2. What writing it out found: `validate` checks disjointness, never representability

The composition needs one function nobody had written — *given the emitted descriptor words, where
does IPA `x` land?* — because that is what a device does. Writing it forced every assumption
[`encode`] makes about its `Layout` into the open, and there were four. None is reachable at
today's constants. Every one of them **mis-maps silently**: no fault, no failed check, because
`verify_encoding` re-derives its expectation exactly as `encode` derives the descriptor, so the two
agree on the wrong answer (design-lesson #36, seen from the failure side).

| # | the unstated premise | what violating it does |
|---|---|---|
| **a** | `data_ipa_base` is 2 MiB-aligned | `encode` writes frame `m`'s descriptor at `l3_data[m]`; a walker reads `l3_data[(ipa >> 12) & 511]`. Unaligned, those differ by a constant, so **frame `m`'s IPA resolves to a different frame's PA and permission** — and the frames near the wrap become reachable at addresses *outside* the window `validate` believed disjoint from every other region |
| **b** | no region's span crosses its `L1` entry | `encode` writes `l1[base >> 30]` **once** and indexes its `L2` by `(addr >> 21) & 511`, which **wraps**. A super window crossing a 1 GiB boundary therefore maps its tail frames into the *low* slots of the same `L2` — addresses nothing authorized, reaching real memory. Fails **open** |
| **c** | `frame_size == 4 KiB` (and hence `super_size == 2 MiB`) | `encode` hardcodes an `L3` **page** descriptor and an `L2` **block** descriptor, while `frame_pa`/`frame_ipa` scale by `frame_size`. Any other granule and the descriptor kind and the address arithmetic describe different mappings |
| **d** | `l1_pa >> 48 == 0` and table-aligned | `VTTBR_EL2.BADDR` and `STE.S2TTB` both carry a *truncated* base. Above the field, **both walkers walk a table `encode` never wrote** — and they agree with each other, so the rung-3 "one regime, two walkers" round-trip cannot see it |

Premise **d** is the one that matters most for this rung specifically, because it is exactly the
join: rung 3's `the_vttbr_seam_recovers_the_table_and_the_vmid` proves the round-trip **under
`assume(pa >> 48 == 0)`**, and nothing discharged that assumption. The seam was proven; its premise
was assumed in the harness and unchecked in the code.

**The repair is where the other three checks already live.** `Layout::validate` gains
[`EncodingViolation::WindowUnaligned`], [`RegionCrossesL1`] and [`TableUnnameable`], each fail-loud
at the same place the metal already halts on `validate` (`build_stage2_from_p2m`), and each proven
total over a symbolic `Layout` — the I-3 idiom, one rung out. `frame_size` is checked in the same
arm as (a), since 4 KiB is the granule `BALEEN_STAGE2` declares and `encode` is written against.

## 3. The three design calls

### 3a. At which level it composes: the descriptor **words**, end to end

The cheaper option was to compose through the already-proven decode-seam interface — state the
theorem over leaf maps and `Stage2Binding`s and let the descriptor bits be somebody else's link.
That would have converted the citation into a theorem too, and it would have left **every one of
§2's four premises uncovered**, because all four live precisely in the step from "the leaf map says
frame `m`" to "a walker starting at `l1_pa` and given `ipa` arrives at frame `m`". That step is the
one nothing had ever written down: `stage2_encoding` proves individual descriptors round-trip and
`verify_encoding` checks the emitted table at boot *through the same derivation `encode` used*.

So the composition walks the words. Two new pure functions, deliberately independent of each other
and of `encode` (design-lesson #36, three readings now rather than two):

```rust
// hv-s2/src/arm64.rs
pub fn walk(l1_pa: u64, ipa: u64, fetch: impl Fn(u64, u64) -> u64) -> Option<Reach>;
pub fn window_reach(layout: &Layout, leaves: &[Option<Perm>], supers: &[Option<Perm>], ipa: u64)
    -> Option<Reach>;
```

[`walk`] is what a walker does — read the descriptor words. [`window_reach`] is what the *layout*
says should happen, written from the windows and the leaf maps with no reference to descriptor
encoding at all. The theorem is that they agree for **every** IPA, and it is what makes "the model
authorizes frame `m`" and "the device lands at `frame_pa(m)`" the same statement.

### 3b. The join: one derivation of the table base, from the `Layout` the emitter is handed

Before this rung `build_stage2_from_p2m` computed `vttbr(layout.l1_pa, vmid)` and handed it to
`register_domain_binding`, which computed `s2ttb = vttbr_table(vttbr)` — **the table base derived
twice, the second time out of a register encoding**. It was witnessed at boot by `walk_stage2` in
four phases across rungs 3 and 4b, and proven nowhere; §2(d) is the hole that left.

Now [`hv_s2::smmu::stage2_handles`] derives both from the one `Layout`:

```rust
pub fn stage2_handles(layout: &Layout, vmid: u64) -> Result<Stage2Handles, HandleError>
//    -> { vttbr: u64, binding: Stage2Binding }
```

`binding.s2ttb` **is** `layout.l1_pa` — not a value recovered from the VTTBR — and a base neither
register can name exactly is **refused**, never truncated. The proof then says the two consumers
provably agree (`vttbr_table(h.vttbr) == h.binding.s2ttb`, `vttbr_vmid(h.vttbr, ..) ==
h.binding.vmid`) rather than assuming it, and `hv-metal` no longer contains a second derivation to
disagree with.

**Behaviour-nil on the CPU path, and pinned.** The `VTTBR_EL2` value is byte-identical to what the
metal computed before — a golden test asserts it against the deployed layout, the same way rung 3's
`VTCR_EL2` refactor was pinned to `0x8002_3559`.

### 3c. The walk moves under the fence

`walk_stage2` lived in `hv-metal` and was `unsafe`. Its *logic* — level indexing, the block/page
fork, applying the offset within the leaf — is pure, and it is the witness's own statement of where
a DMA should land, so leaving it in the metal meant the expectation the boot asserts against was
itself unproven.

It moves to `hv_s2::arm64::walk`, generic over `fetch(table_pa, index) -> u64`. **What it costs the
metal is nothing it should have kept**: the `unsafe` volatile read stays in `hv-metal` (a raw
pointer dereference is exactly what the metal is for), and what leaves is the walk. What the metal
gains is that its witness now asserts against a proven function, and the *same* function the
composition theorem is stated over — so the boot witness and the proof cannot be about two
different walks.

## 4. What is proven — `hv-verify::device_path_composition`

Six Kani harnesses on the shipped `hv_s2` emitter, the shipped `hv_s2::smmu` derivation and the
shipped `hv_core::device` relation. Kani **59 → 65**.

| harness | s | what it closes |
|---|---|---|
| `the_walk_lands_where_the_windows_say` | 5 | **∀ IPA**: a walk of the words `encode` wrote lands exactly where the layout's windows say, or faults exactly where they say. The link nothing had — and it **failed on its first run** (§2, the ceiling) |
| `the_two_consumers_are_pointed_at_one_table` | 0.6 | **∀ table base and ∀ VMID**: the CPU's `VTTBR_EL2` and the device's `S2TTB` name the table the emitter was handed — or the handles are refused. **Failed on its first run too** (§2e) |
| `a_device_reaches_exactly_the_memory_its_domain_reaches` | 38 | **THE THEOREM. ∀ StreamID and ∀ IPA**, over two domains' table sets at once: relation → derived table bytes → STE decode seam → a walk of the descriptor words = exactly the memory the domain the model assigned it to reaches, and nothing if it assigned it to no one |
| `a_device_never_reaches_an_unauthorized_frame` | 31 | **∀ model edge set, ∀ grant table, ∀ frame and ∀ StreamID**: end to end from `hv-core`'s edges to the bus master's bytes — a device never reaches a frame its holder neither owns nor holds a grant for, **at the permission it got** |
| `the_composition_is_not_vacuous` | 13 | there **exists** a reachable `(sid, address)`: an assigned device really lands on its domain's writable frame, gets `Ro` on the read-only one, and nothing on the unmapped one |
| `binding_the_wrong_domain_reaches_the_wrong_memory` | 15 | the theorem **can fail**, and the way it fails is the isolation content: one field of one entry naming the other domain's tables, and the device reaches nothing of its own domain's (#71) |

**The two quantification axes are carried by different harnesses, deliberately and measured.** The
address axis (∀ 2⁶⁴ addresses, bounded *mapped* frames) is the direction that says nothing else is
reachable; the model axis (∀ edge set and grant table, bounded frame index) is the direction that
says what is reachable is authorized. Priced together they do not terminate — measured, not
assumed. Neither is dropped, and this paragraph is here because a silently-dropped axis reads as a
covered one (design-lesson #79).

**Sized to two domains, two devices, a four-entry stream table and three mapped base frames.** Two
domains because "the *other* domain's memory" is the whole isolation content and needs a second set
of tables to be wrong about; the stream-table size axis is closed as rungs 2–4b close it (the
builder's offset is size-generic and proven at the deployed `BUS0_LOG2SIZE`, and `hv-metal` runs
`table_refines_the_relation` over the real 256-entry table after every derivation).

### 4a. The cost lever, measured — and it is **not** the one rung 4b found

Rung 4b's lesson (#83) was that a symbolic *index* costs far more than a symbolic value, and it
predicted this rung would be expensive: a composed theorem quantifies over an address, which is an
index into descriptor tables. **That prediction was wrong, and the measurement says something
different.**

* A fully symbolic 2⁶⁴ IPA walked through three 512-entry tables: **0.18 s**. The address axis is
  nearly free.
* `encode` alone, no walk, no symbolic address: **did not terminate in ten minutes.** The cost was
  three clear loops — `for slot in table.iter_mut() { *slot = 0 }`, 512 iterations each, which the
  symbolic executor unrolls one store at a time. Rewritten as `*table = [0; TABLE_ENTRIES]` —
  identical semantics, a bulk store — the same harness runs in **0.5 s**.
* The new `Layout::validate` arms, written idiomatically as a loop over a chained iterator
  (`Chain<array::IntoIter, option::IntoIter>`), cost **minutes**. Flat sequential checks: nothing.

**The generalizable form: when a harness drives an emitter rather than a decision function, the
price is in how the emitter *writes*, not in what the proof *asks*.** A bulk assignment and a slot
loop are the same program and are not the same proof obligation. Both fixes are in the shipped code
and both make it plainer, which is the good case; the alternative would have been to shrink the
theorem until the loops stopped mattering.

**Budget.** The six add ≈103 s locally, against a local full-suite ≈14 min and a measured CI
`kani proofs (PR)` of 27.7 min against a 45-minute limit. Expect ≈31 min, ≈14 min of headroom.

## 5. What this rung does **not** claim

* **The metal still hands over the `Layout`, and that is still a construction argument.** §0.1,
  unchanged: `l1_pa: tables.l1.0.as_ptr() as u64` is one line no proof reads. Everything downstream
  of it is now a function of that one value, which is the most this rung can do.
* **The frame population is bounded even though the address space is not.** Three base frames and
  two super frames are symbolic in the composed harnesses; the addresses of every other frame are
  covered in the direction that matters (the theorem requires the walk to fault there), but a
  *mapped* population beyond that is not driven. The ∀-frame direction is
  `a_device_never_reaches_an_unauthorized_frame`'s, at its own bounded address.
* **`window_reach` has no runtime companion.** The table half of the arc does — `hv-metal` runs
  `table_refines_the_relation` over the real stream table after every derivation — but the reach
  half would need every domain's leaf map retained past emission, which the metal deliberately does
  not do. The reach statement is therefore proven and not boot-checked, and the boot's evidence for
  it stays rung 3's and rung 4b's landing witnesses.
* **The walk is concrete to the deployed regime.** Start level 1, three levels, 4 KiB granule, one
  512-entry `L1`. What keeps that honest is `validate`'s granule arm plus the compile-time pin
  `1 << BALEEN_STAGE2.ipa_bits == ADDRESSABLE`; a regime-generic walker is not proven and is not
  needed while `BALEEN_STAGE2` is one declaration.
* **Memory attributes are not part of `Reach`.** Whether a mapping is Normal-WB or Device-nGnRnE is
  Phase I-3's `T_dev`, proven ∀-address there and untouched here. `Reach` carries where and at what
  access, which is what the isolation sentence is about.
* **Everything rungs 3 and 4b did not claim, they still do not.** The two consumers are not
  simultaneous; one device, one StreamID; the VMID field and the stage-2 TLBI remain unwitnessed on
  QEMU; a `DeviceAssign` to a domain with no emitted image halts.
* **Phase I-3's disjointness harnesses now quantify over a smaller set, and that is the point.**
  `stage2_device_region`'s theorems are of the form *"if `validate` returns `Ok`, then …"*, so
  narrowing what `validate` accepts narrows what they cover. Nothing they proved has been weakened
  — the set they range over is now exactly the set the emitter can express, which is the set the
  metal was always in.
* **This rung adds no metal behaviour.** Like II-1a and rung 4a, it is behaviour-nil: the boot test
  is byte-for-byte unchanged, and the two refactors that could have changed something (the join and
  the walk) are pinned — the join by a golden test asserting the `VTTBR_EL2` value and the binding
  the old two-derivation code produced, the walk by the boot witness it serves.

---

*See also: `hv-s2/src/arm64.rs` (`walk`, `window_reach`, `Layout::validate`), `hv-s2/src/smmu.rs`
(`stage2_handles`, `device_reach`), `hv-verify/src/lib.rs` `device_path_composition`,
`docs/SMMU-STREAM-DERIVATION.md` (rung 4b — the relation this composes with),
`docs/SMMU-TRANSLATION.md` (rung 3 — the binding), and `docs/STAGE2-REFINEMENT-FORALL-N.md` (the
`p2m` → leaf map theorem this ends at).*
