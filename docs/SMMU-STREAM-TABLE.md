# SMMU rung 2 — ∀-StreamID stream-table default-deny

*The SMMU arc, rung 2. Rung 1 (PR #91) closed the pre-enable DMA window; this rung makes the*
*hypervisor's answer to a bus master **no** by default once the SMMU is actually translating, and*
*proves it — over all 2³² StreamIDs in the builder, and on the hardware for the device that exists.*

---

## 1. The hole, restated precisely

Every isolation result baleen has is about **CPU** accesses. Stage-2 constrains what a guest's loads
and stores reach; a DMA-capable device never consults `VTTBR_EL2` at all. Rung 1 established the
first half of the answer: while `SMMU_CR0.SMMUEN == 0`, `SMMU_GBPA` decides what happens to a
transaction, and its reset value is **bypass** — so from power-on until the hypervisor configures the
SMMU, every device can write anywhere. Rung 1 sets `GBPA.ABORT` before any device is given Bus Master
Enable.

But `GBPA` stops applying the moment the SMMU starts translating. From then on the decision is made
by the **stream table**: the transaction carries a StreamID (on PCIe, the RequesterID), the SMMU
indexes a table with it, and the 64-byte **Stream Table Entry** there says abort, bypass, or
translate. A stream table whose unconfigured entries *bypass* is a total isolation hole with an IOMMU
switched on in front of it.

So rung 2's property is:

> **∀ StreamID: unless this hypervisor deliberately bound it, the SMMU aborts its traffic.**

## 2. Three denial arms, one total function

"Deny by default" is not one condition. A device escapes if **any** of three go wrong:

1. the StreamID is **outside** the configured table (`STRTAB_BASE_CFG.LOG2SIZE`) — architecturally
   `C_BAD_STREAMID`, *provided* the announced size does not exceed the allocation, in which case the
   SMMU would instead fetch entries from past the table;
2. the entry is **invalid** (`STE.V == 0`) — `C_BAD_STE`. This is what a zeroed table is, which is why
   "allocate zeroed" is the fail-closed default and not merely tidy;
3. the entry is valid but `Config[2]` is clear — an explicit abort STE.

`hv_s2::smmu::verdict` folds all three into one **total** function over an arbitrary
`(table, log2size, sid)`, so there is a single place to prove the disjunction covers every StreamID
rather than three conditions to keep in step. Same idiom as I-4's `SpanConflict` ruling: make the
fail-closed answer the only answer a total function can return outside the permitted set, then prove
totality instead of arguing it.

Baleen's table is **linear, 256 entries** — exactly every `(device, function)` on PCIe bus 0, since a
RequesterID is `(bus << 8) | (device << 3) | function`. Sizing it to the bus rather than to the
SMMU's `IDR1.SIDSIZE` (16 here — a 4 MiB linear table) is not a shortcut: arm 1 is a *stronger*
denial than an entry that merely happens to be zero, and it costs 16 KiB.

## 3. Two arrows, and the one that is easy to fake

```text
   builder writes bytes  --(A)-->  stream table in RAM  --(B)-->  the SMMU's decision
```

**(A) is proven.** `hv-verify::smmu_stream_table` — **ten** Kani harnesses over the shipped
`hv_s2::smmu`, with the StreamID (all 2³²) and the entry words (all 2⁶⁴) fully symbolic. Nine run at
bounded table size (`log2size <= 2`, the same shape as the `DOMS=3 / FRAMES=4` grant proofs); the
tenth runs at the 256-entry size the metal actually deploys.

| harness | what it closes |
|---|---|
| `zeroed_stream_table_denies_every_streamid` | ∀ 2³² StreamIDs: a zeroed table permits none |
| `the_deployed_stream_table_denies_every_streamid` | the same, at the **256-entry size actually shipped**, and denied by the zeroed *entry* rather than by a range check |
| `binding_one_stream_leaves_every_other_denied` | ∀ other StreamID denied — **and** the bound one permitted, so the harness cannot pass by `bind` doing nothing |
| `unbind_restores_deny_for_every_streamid` | the bypass→deny transition restores the default, not some other aborting state |
| `an_out_of_range_bind_changes_no_word` | a refused bind writes nothing — it cannot authorise a neighbour by truncating into it |
| `a_bind_touches_only_its_own_entry` | ∀ word outside the entry unchanged — a spill would silently validate the next StreamID |
| `an_under_allocated_table_denies_every_streamid` | the one **fail-open** shape (configured larger than allocated) denies, and `bind` refuses to create it |
| `an_ste_permits_iff_valid_and_not_configured_to_abort` | ∀ 2⁶⁴ entry words: permits **iff** `V` and `Config[2]` — a biconditional, so neither direction can rot |
| `the_constructors_decode_to_their_names` | emit seam meets decode seam; the bypass STE is pinned as *unconfined* |
| `the_register_encodings_match_the_table_they_describe` | ∀ size and ∀ address: `STRTAB_BASE_CFG` announces linear + the size the table was built for |

Two things about (A) are worth stating rather than leaving to be inferred.

**The deny is asserted *by reason*, not just as `!permits()`.** A stream table whose storage were
smaller than its configured size would also deny every StreamID — via `OutOfRange` — so a bare
`!permits()` would pass just as happily on a mis-sized table as on a correctly-sized empty one. The
two zeroed-table harnesses therefore require `Invalid` (a zeroed *entry*) inside the range and
`OutOfRange` only outside it. Confirmed load-bearing: allocating the deployed table at half its
configured size makes the harness fail.

**The deployed size is a shared constant, not a coincidence.** `hv_s2::smmu::BUS0_LOG2SIZE` is both
what the proof instantiates and what `hv-metal` allocates and configures from, with `const _`
assertions binding the allocation's size and alignment to it. A size proven in a harness but not
shipped, or shipped but not proven, is the gap that arrangement removes (design-lesson #14c — one
derivation, no drift).

**Why there is no Verus mirror.** The standing division of labour is: Kani closes *all values at
bounded size*, Verus closes *all sizes*. Here the unbounded axis — the StreamID, 2³² of them — is
exactly the axis Kani closes, and the size axis is not a dimension of the reachable state space at
all: the deployed table has **one** size, fixed at compile time, pinned by `const _` against its
allocation, and the only function that can re-announce it (`set_announced_table_size`) refuses
anything above the allocation. So "∀ size" has nothing to quantify over. Same ruling shape as W^X
(design-lesson #52), where the whole content sat at the 0↔1 boundary and a mirror would have added
ceremony rather than coverage. If rung 3 makes the table 2-level or its size configuration-driven,
that ruling expires.

**(B) is not proven, and cannot be by anything in this repo.** A green Kani run is entirely
compatible with *"the device never reached the stream table at all"* — which is precisely how an
∀-StreamID deny passes vacuously. Arrow (B) is discharged by the metal witness, and the emit and
decode seams are kept independent (`bypass_ste` writes, `decode` reads, neither derived from the
other) so the round-trip is not tautological — the same repair GAP-A made for the descriptor emitter.

## 4. The metal witness — five phases, one boot, one device

Rung 1's control differed from its deny in the **machine** (SMMU or no SMMU), which leaves a lot
unexplained between two runs. Rung 2 tightens the difference to a single 64-byte entry:

| phase | `STE[sid]` | table announced as | required outcome |
|---|---|---|---|
| 1 — through-STE control | bypass (`V=1`, `Config=0b100`) | 256 entries | the DMA **lands** |
| 2 — default-deny | zeroed (`V=0`) | 256 entries | **aborted**, `C_BAD_STE` for `sid` |
| 3 — StreamID-specific | zeroed, *neighbour* bound to bypass | 256 entries | **aborted**, `C_BAD_STE` |
| 4 — re-permit | bypass again | 256 entries | the DMA **lands** again |
| 5 — out-of-range | still bypass | **1 entry** | **aborted**, `C_BAD_STREAMID` |

Phases 1 and 4 additionally require that the SMMU recorded **no** event — a permitted transaction
faults nothing, which is a free discriminator.

* **Phase 1 is why the rung means anything**, and it is first for that reason. A wrong `LOG2SIZE`, a
  mis-aligned `STRTAB_BASE`, an `SMMUEN` that never took, or a StreamID that is not the device's
  RequesterID all yield "aborted". A DMA that gets *through* a deliberately-configured entry could
  only have got through **that entry**, so phase 1 rules out every one of them at once.
* **Phase 3 is the ∀-StreamID claim's on-metal half.** Kani proves the builder permits exactly the
  StreamID asked for; phase 3 shows the hardware agrees.
* **Phase 4 keeps phases 2 and 3 from being about a wedged SMMU.** Every "aborted" is also consistent
  with the device having died or the queue having stalled, and a sequence that only tightens can
  never tell. Re-permitting the same StreamID and requiring the DMA to land again closes it: the
  mechanism is demonstrably still willing to say yes.
* **Phase 5 witnesses the range arm with a permissive entry in place.** The entry says yes and the
  range check says no; only one of them can explain the abort, and `C_BAD_STREAMID` rather than
  `C_BAD_STE` is the SMMU stating which.

Every denial is **attributed** — the event queue's record names the event class *and* the StreamID —
rather than inferred from a sentinel that did not change.

### Ordering is still the property

The all-deny table is built and published *before* `CR0.SMMUEN` is written, and `GBPA.ABORT` governs
everything before that. There is no instant, from reset to translating, in which a bus master would
be let through. As in rung 1, reaching the same end state in the other order leaves the hole open and
no end-state marker distinguishes them.

## 5. What was probed, because the checks passed first try

The recurring failure mode across this program has not been wrong logic — it has been **checks that
could not have failed**. Every check above was deliberately broken and confirmed to go red:

| mutation | result |
|---|---|
| deployed table allocated at half its configured size | `the_deployed_stream_table_denies_every_streamid` fails — the deny is by *reason*, not by absence |
| never bind the bypass STE | phase 1 stops landing — the through-path is caused by the STE |
| never unbind | phase 2 lands — the denial is caused by zeroing the entry |
| bind the device's own StreamID instead of the neighbour | phase 3 lands — the permit is per-StreamID |
| **bind the wrong StreamID throughout** | **every** phase loses its outcome — the whole result rests on the RequesterID mapping being right |
| never write `CR0.SMMUEN` | every phase reports "aborted" — *the vacuous deny itself*, caught by phase 1 |
| never shrink the announced table | phase 5 lands — the out-of-range denial is caused by the range check |
| `decode` treats `V == 0` as bypass | 5 of 9 Kani harnesses fail (probed before the tenth was added) |
| `bind` spills into the next entry | 2 of 9 fail |
| drop the allocation check in `entry_offset` | 1 of 9 fails |

One check found a real defect while being built: a single aborted 8-byte `edu` transfer produces
**two** event records, so reading "the first event in the queue" returned a record two phases old.
The event queue is now drained before each observed transfer. That bug was only visible because the
assertion demanded the specific event *type and StreamID* rather than merely that some event existed.

Two more things worth recording:

* **Rung 1's `IDR0.S1P`/`S2P` constants were swapped** (the architecture has `S2P` at bit 0). It
  changed no result — QEMU's SMMU sets both, so `supports_stage2()` answered `true` either way —
  which is exactly why it survived: a check whose two inputs are both set cannot discriminate between
  them. Corrected here.
* **QEMU aligns `STRTAB_BASE` down to the table size itself**, so a mis-aligned base is silently
  corrected by the model and the misalignment probe could not discriminate on this platform. The
  architectural alignment (the larger of the table size and 64 bytes) is instead pinned at **compile
  time**, by a `const _` assertion against `hv_s2::smmu::base_alignment`. On silicon an under-aligned
  base is *truncated* to a different table, every StreamID denies for an unrelated reason, and the
  result would be vacuous — so QEMU not catching it is precisely why the static check exists.

## 6. What rung 2 does **not** claim

* **Nothing here confines a permitted device.** A bypass STE places no constraint on where the device
  writes; `StreamVerdict::stage2_unconfined` names that in the type and a Kani harness pins it.
  Rung 2's claim is exactly *"nothing reaches memory unless this hypervisor bound its StreamID"*, not
  *"a bound device is confined"*. Conflating the two is how a headline gets ahead of its artifacts.
* **The `∀-StreamID` proof is about the builder**, at bounded table size, with the StreamID unbounded.
  The hardware arrow is the metal witness, for the one device that exists on this machine.
* **Invalidation discipline is exercised, not proven.** `CMD_CFGI_STE` + `CMD_SYNC` are issued around
  every entry edit and the boot would visibly fail without them (a stale cached STE would make phases
  2 and 3 land), but there is no ∀-argument that every future edit site remembers to.

## 7. Rung 3 — **done**, see `docs/SMMU-TRANSLATION.md`

Translation proper: `STE.Config = 0b110` with `S2TTB` pointing at the `p2m`-derived Stage-2 tables
under the domain's `S2VMID` — where `hv-s2`'s existing ∀-address refinement covers the device path
*for free*, because `encode_leaf_descriptors_follow_the_seam` and `stage2_leaf_authorized.rs`
constrain the **table**, not the **walker**. The positive control is stronger there too: the DMA must
land at the address the *table* says, not the one the device asked for, and both addresses are read
back.

The no-Verus-mirror ruling in §3 **stands**: rung 3 left the table linear and its size a compile-time
constant. What rung 3 did add is a second consumer for the *translation regime* — the STE's copy of
what `VTCR_EL2` gives the CPU — which is a new ∀-quantified agreement proof, not a size axis.

---

*See also: `hv-s2/src/smmu.rs` (the builder), `hv-verify/src/lib.rs` `smmu_stream_table` (the
proofs), `hv-metal/src/smmu.rs` (registers, queues, invalidation), `hv-metal/src/dmawitness.rs` (the
five phases), `hv-metal/boot-test.sh` (the markers), and `docs/QEMU-AND-METAL.md` for what an
emulated run does and does not establish.*
