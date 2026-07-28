# SMMU rung 3 — translation: one proven `p2m`, two consumers

*The SMMU arc, rung 3. Rung 1 (PR #91) closed the pre-enable DMA window; rung 2 (PR #92) made the*
*answer to an unbound bus master **no**. Both left every permitted device **unconfined**. This rung*
*binds a device's StreamID to a **domain** — the same VMID-tagged Stage-2 tables that domain's CPU*
*already runs behind — so that for the first time baleen constrains **where** a device may write.*

---

## 1. What was still open after rung 2

Rung 2's claim is exactly *"nothing reaches memory unless this hypervisor bound its StreamID"*. The
entry it binds is a **bypass** entry (`STE.Config = 0b100`): the device's own address goes straight
onto memory, unmodified and unchecked. `StreamVerdict::stage2_unconfined` says so in the type. So
after rung 2 the hypervisor could say *no*, and could say *yes*, and had no way to say **"yes, but
only here."**

That is what rung 3 adds, and the design call it turns on was made before any code:

> **Does the device walk the same Stage-2 tables the domain's CPU walks, or its own?**

It walks the **same** ones. `STE.S2TTB` points at `STAGE2_SETS[set].l1` — the table
`build_stage2_from_p2m` emitted from the proven `p2m` and `VTTBR_EL2` installs — under that set's
VMID. One proven `p2m`, two consumers.

The alternative (device-private tables) is easier and proves much less: it would need a second
emitter, a second refinement argument, and it would leave "the device is confined to the domain's
memory" as prose relating two different objects. With the shared table there is only one object, so
`hv-s2`'s ∀-address refinement covers the device path **verbatim** — the theorem constrains the
*table*, not the *walker*.

Two arms fall out of that choice for free, and neither is available to a device-private design:

* an IPA the domain does not own has **no descriptor**, so the device takes a translation fault;
* a frame the emitter mapped **read-only** refuses the device's *write*, for the same reason and by
  the same bits it refuses the guest's.

## 2. The genuinely new surface: stream → domain **binding**

The refinement carrying over means rung 3 re-proves none of it. What nothing before this rung covers
is the binding itself:

> **∀ StreamID: the memory a device reaches is exactly the memory the domain its STE names reaches.**

This is the analogue of the `VTTBR_EL2` install, and its failure mode is not a fault — it is a
**wrong domain's memory**. Three fields have to be exactly right, and all three silently truncate if
they are not:

| field | wrong value gives |
|---|---|
| `STE.S2TTB` | a *different table* — some other domain's, or garbage read as descriptors |
| `STE.S2VMID` | TLB entries tagged as another domain's |
| `STE` word 2's regime (`S2T0SZ`/`S2SL0`/`S2TG`/`S2PS`) | the same table walked *differently* — a start level one off reads leaf descriptors as table descriptors |

So every one of them is **refused rather than approximated** by `hv_s2::smmu::stage2_ste`, and every
one is proven to round-trip through an independent decode seam.

### 2a. One regime, two walkers

The third row is the one that would not have been noticed by reading the code. Until this rung the
CPU's translation regime was a literal in `hv-metal`:

```rust
const VTCR_EL2: u64 = 0x8002_3559;   // 4 KiB, 39-bit IPA, start level 1, 40-bit PA
```

with exactly one consumer. Rung 3 gives it a second: the SMMU walks the same tables under the STE's
own copy of the same parameters. Two walkers over one table under *different* parameters is not a
degraded translation, it is a different one. So the parameters became one declaration —
`hv_s2::arm64::BALEEN_STAGE2` — with two **independent** encodings (`vtcr_el2` and `stage2_ste`), and
a Kani harness proves they decode to the same regime for *every* regime. The metal's `VTCR_EL2` is
now `vtcr_el2(&BALEEN_STAGE2, BALEEN_VMID_BITS)` resolved at compile time, pinned byte-for-byte to
`0x8002_3559` by a golden test — the refactor is required to be behaviour-nil on the CPU path.

**And the granule is refused, not guessed.** `VTCR_EL2.TG0` encodes 4 K/64 K/16 K as
`0b00/0b01/0b10`. `STE.S2TG`'s encoding for the two large granules is *not* something this repo has
verified against the hardware it runs on — and at baleen's 4 KiB granule both fields are `0b00`, so a
naive field copy would be indistinguishable from a correct one (design-lesson #71: a check whose two
inputs are equal cannot discriminate). Shipping an unverified mapping under a proof would make the
proof prove the wrong thing, so `stage2_ste` **refuses every granule but 4 KiB**, and the refusal is
part of what is proven.

### 2b. Where the binding's VMID comes from — a modelling error the proof found

The first draft put the VMID *width* (`VTCR_EL2.VS`) inside `Stage2Regime`, alongside the rest of the
parameters. The ∀-regime agreement harness failed immediately, and it was right to: **the STE has no
`VS` field.** `S2VMID` is always 16 bits wide, so a 16-bit-VMID regime encoded into an entry decodes
back as an 8-bit one, and "the two walkers share one regime" was false as stated.

The repair is not to weaken the theorem but to move the field. Width is a property of the CPU's
configuration; the coupling it was there to enforce — an 8-bit-tagging CPU must not hand the SMMU a
16-bit VMID, or two domains alias under truncation — is enforced instead at the **derivation**:

```rust
vmid: vttbr_vmid(vttbr_a, BALEEN_VMID_BITS)   // masked to the width the CPU actually tags with
```

The metal obtains both halves of the binding by reading them back out of the `VTTBR_EL2` value the
domain's CPU would be given (`vttbr_table` / `vttbr_vmid`, a proven seam). "The device walks the same
table as the domain's CPU, under the same VMID" therefore holds **by construction**, not by two
derivations agreeing.

## 3. What is proven — `hv-verify::smmu_stream_binding`

Eight new Kani harnesses on the shipped `hv_s2` builders (Kani **47** total, up from 39):

| harness | what it closes |
|---|---|
| `the_device_and_the_cpu_walk_under_one_regime` | ∀ regime: an emitted STE's walk parameters decode to exactly what `VTCR_EL2` gives the CPU — or the encoder refuses. Includes the granule refusal, and a non-vacuity clause pinning the deployed regime as encodable |
| `the_vttbr_seam_recovers_the_table_and_the_vmid` | ∀ table and ∀ VMID: `vttbr_table`/`vttbr_vmid` recover what `vttbr` wrote, and the width mask is what keeps a VMID the CPU does not tag with off the device side |
| `a_bound_stream_names_exactly_the_domain_it_was_given` | ∀ table base and ∀ VMID: every field round-trips; the stream is `Stage2Only`, permits, and is **not** `stage2_unconfined` |
| `binding_a_stream_to_a_domain_leaves_every_other_denied` | ∀ other StreamID: rung 2's default-deny survives translation — no other stream reaches *any* domain's memory |
| `rebinding_a_stream_leaves_no_trace_of_the_previous_domain` | ∀ pair: a rebind cannot leave the old table under the new VMID (a table nobody authorized) |
| `unbinding_a_domain_binding_restores_the_deny` | ∀ StreamID: teardown returns to the same fail-closed default the table starts in |
| `a_binding_that_cannot_be_named_exactly_is_refused_and_writes_nothing` | ∀ address: a table pointer the field cannot carry exactly leaves the entry **denying** — it does not name a smaller permission, it names a different table |
| `no_entry_decodes_as_a_binding_unless_it_is_a_stage2_ste` | ∀ 8 arbitrary words: memory this hypervisor did not write is never read as an authorization |

Two of them were confirmed load-bearing by removing the fix: dropping the alignment check fails
`a_binding_that_cannot_be_named_exactly_…`, and masking the VMID to 8 bits inside the encoder fails
`a_bound_stream_names_exactly_…`.

**What none of it proves** is that the SMMU reads those bits the way this crate writes them. That
arrow is the metal's, and rung 3's control is what discharges it.

## 4. The metal witness — seven phases, one boot, one device, two domains

Rung 2's control could only show the device *reaches* its STE. Rung 3's shows translation actually
happened, because the address the device issues and the address the data arrives at are **different
addresses and both are read back**:

> Map IPA X → PA Y with Y ≠ X, tell the device to write X, and require the sentinel at **Y** to change
> **and** the one at **X** not to. "Something landed" is not enough — a bypass STE also lands.

| phase | `STE[sid]` names | device asks for | required outcome |
|---|---|---|---|
| 1 — translation control | A's tables, VMID 1 | A's writable frame's IPA | lands at **the PA the table says**, not at the IPA |
| 2 — confinement | A's tables | an IPA A does not own | **aborted**, `F_TRANSLATION` naming that exact address |
| 3 — permission | A's tables | A's **read-only** frame's IPA | **aborted**, `F_PERMISSION` |
| 4 — wrong domain | B's tables, VMID 2 | **A's** writable frame's IPA | **aborted**, and A's memory at that PA untouched |
| 5 — right domain | B's tables | B's writable frame's IPA | lands in **B's** frame |
| 6 — back to A | A's tables, VMID 1 | A's writable frame's IPA | lands in A's frame again |
| 7 — restore | nothing (unbound) | A's writable frame's IPA | **aborted**, `C_BAD_STE`; the table denies every StreamID |

Phases 1, 5 and 6 additionally require that the SMMU recorded **no** event.

* **Phase 1 is the control and it is first**, as in rungs 1 and 2 (design-lesson #70). If translation
  cannot be made to work, none of the denials below mean anything and must not be reported.
* **Phases 4 and 5 are the isolation content**, and they are why the rung needs two domains. Same
  device, same StreamID, same *issued address* — and whether it reaches memory at all, and whose, is
  decided by one field of one entry.
* **Phase 3 costs nothing new.** The read-only leaf is the one `hv-s2` already emits for a model leaf
  with `writable: false`; the SMMU refuses the write for the same reason the CPU would.
* **Phase 6 is the re-permit** (#70c): every "aborted" is equally consistent with a wedged SMMU, and a
  sequence that only tightens can never tell.

Two supporting decisions are load-bearing enough to name:

**The expectation comes from the table, never from layout arithmetic.** `stage2::walk_stage2` performs
a *software* walk of the emitted descriptors through `hv-s2`'s decode seam — reading the same memory
the SMMU reads — and the phase asserts the DMA landed exactly there. Computing the expected PA from
this repo's own address layout would be asserting the DMA landed where the *emitter's* derivation
says, so a wrong emission and a wrong expectation would agree (design-lesson #36).

**Every observed address is seeded and read back before the transfer.** The "did not land at X" half
of the control is only a check if X is real memory. X is a guest IPA (`0x8000_0000 +`) read as a
physical address, which QEMU `virt`'s default 128 MiB does not back — hence `-m 2048` on that boot.
Measured: with the default RAM the boot dies loudly at that exact address
(`EC=0x25 FAR=0x80002040`), and on a platform that read unbacked memory as zero instead, the seed
read-back would catch it.

## 5. What was probed — twelve mutations, ten red, **two refused to go red**

All seven phases passed on the first boot, which makes the probe battery more important, not less.

| mutation | result |
|---|---|
| bind a **bypass** STE instead of the stage-2 one | phase 1 red, **and the two sentinels swap**: the data lands at the address the device asked for and the table's address is untouched. This is the probe that proves the control tests *translation* and not merely *permission* |
| bind A's stream to **B's** table | phase 1 red — `F_TRANSLATION` on A's IPA; the `S2TTB` decides which memory is reachable |
| skip `CMD_CFGI_STE` | **everything** red, including rung 2's control — QEMU does cache STE configuration, and the invalidation is genuinely load-bearing |
| make A's read-only leaf writable in the model | phase 3 red — the DMA lands, so `F_PERMISSION` is caused by the emitter's `S2AP` bits |
| point phase 2 at a frame the domain **does** own | phase 2 red — the confinement result depends on the address being unmapped |
| phase 4 binds **A** instead of B | phase 4 red — A's memory *is* written, with no fault; the "wrong domain's memory" is reachable exactly when the STE names it |
| compare the fault record's address to the wrong address | phases 2/3/4 red — the address attribution discriminates |
| make the software walk return the issued address | phase 1 red, caught by the **seed read-back** |
| clear `STE.S2R` | phases 2/3/4 red — the denials still happen but become *unattributed*; `S2R` is what records them |
| boot with the default `-m 128` | red, loudly (synchronous external abort at the sentinel address) |
| drop the `S2TTB` alignment check (Kani) | `a_binding_that_cannot_be_named_exactly_…` fails |
| mask the VMID to 8 bits in the encoder (Kani) | `a_bound_stream_names_exactly_…` fails |

### The two that refused to go red — findings about the platform, not passes

Design-lesson #72: when a remove-the-fix probe will not go red, that is information about the
platform, and the guard has to move somewhere the platform is not.

1. **A wrong `S2VMID` changes nothing observable.** Binding domain A's table under VMID 3 leaves every
   phase green. That is *correct behaviour*, not a broken check: the VMID tags TLB entries, and a
   witness made of cold walks cannot exhibit tagging. Its correctness rests on the builder instead —
   the binding is derived from the `VTTBR_EL2` value (§2b), the metal's `bind_stream_stage2` reads the
   entry back through the decode seam and requires it to equal the binding requested, and Kani proves
   the round-trip. **Declared residual: the VMID field is not boot-witnessed on this platform.**
2. **Removing `CMD_TLBI_NSNH_ALL` changes nothing observable.** Two explanations fit — QEMU's
   `CMD_CFGI_STE` may already drop that stream's cached translations, or nothing is cached across
   these operations — and this repo has established neither. The command stays because the
   architecture requires it when the tables a stream reaches change; it is **reasoned, not witnessed**,
   the same standing as the cache maintenance in `scrub_frame`.

## 6. What rung 3 does **not** claim

* **It does not extend the ∀-address refinement.** That theorem carries over verbatim because it
  constrains the table; nothing here re-proves or strengthens it. The new machine-checked surface is
  the binding, and it is honest to say the *proof* content of this rung is thinner than rung 2's.
* **The two consumers are not simultaneous.** The device and the CPU consume the *same tables built by
  the same function from the same `p2m`*, but the witness drives the device while no vCPU of that
  domain is running. A guest-observed version — the guest reading, at the same IPA, the bytes a device
  delivered — is a further rung, not this one.
* **One device, one StreamID.** QEMU's `edu` is the only bus master in the machine. Nothing here
  witnesses two devices bound to two different domains at once.
* ~~**No `hv-core` model of DMA.** Device→domain assignment is metal configuration; the model knows
  nothing about bus masters, so there is no ∀-N statement that a device is assigned to at most one
  domain, and no hypercall by which a guest could ask for one.~~ **CLOSED IN THE MODEL by rung 4a**
  (`docs/SMMU-DEVICE-ASSIGNMENT.md`): `hv-core` now carries the device→domain relation, two
  authority-gated transitions, and the lifecycle coupling `assigned ⇒ Live` — proven ∀-values on the
  shipped code (Kani), ∀-size (Verus), over every reachable state (the enumerator), and quantified
  in Tier-D non-interference. ~~**Still open:** the metal does not yet *derive* its stream table
  from that relation — the STE is still bound by hand in the witness.~~ **ALSO CLOSED, by rung 4b**
  (`docs/SMMU-STREAM-DERIVATION.md`): the whole table is now derived from the relation in
  `teardown::dispatch`'s post-dispatch funnel, proven as a biconditional, and witnessed by Arc-0's
  lifecycle matrix run on the device path — destroy a domain holding a device and its bus master
  reaches nothing of the reborn tenant's memory.
* **Invalidation discipline is exercised, not proven** — unchanged from rung 2, and now weaker in one
  respect, per §5's second finding.

---

*See also: `hv-s2/src/arm64.rs` (the regime), `hv-s2/src/smmu.rs` (the binding builder),
`hv-verify/src/lib.rs` `smmu_stream_binding` (the proofs), `hv-metal/src/smmu.rs` (registers,
invalidation), `hv-metal/src/stage2.rs` (`walk_stage2`), `hv-metal/src/dmawitness.rs` (the seven
phases), `hv-metal/boot-test.sh` (the markers), `docs/SMMU-STREAM-TABLE.md` (rung 2), and
`docs/QEMU-AND-METAL.md` for what an emulated run does and does not establish.*
