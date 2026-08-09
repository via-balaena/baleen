# SMMU rung 4b — the metal derives the stream table

*The SMMU arc, rung 4b, and the arc's last piece with machine-checkable content. Rung 1 (PR #91)*
*closed the pre-enable DMA window; rung 2 (#92) made the answer to an unbound bus master **no**;*
*rung 3 (#93) confined a bound one to a domain's proven `p2m`; rung 4a (#94) put the device→domain*
*relation in `hv-core` and proved it. This rung is the **arrow between the last two**: the stream*
*table stops being a configuration and becomes a **refinement** of that relation, the way the*
*Stage-2 image is a refinement of the `p2m`.*

---

## 1. What rung 4a left open, precisely

`docs/SMMU-DEVICE-ASSIGNMENT.md` §8 says it in one line: *"Assignment is now a proven relation with
**no consumer**."* `hv-metal`'s witness called `bind_stream_stage2` **by hand** with a domain chosen
by the witness, so:

* nothing said the table's entries were the assignments the model had actually recorded;
* nothing said an assignment the model recorded reached the hardware at all;
* `domain_destroy`'s device sweep — the mechanism that stops a dead tenant's bus master — had no
  effect on any STE, because no STE was derived from anything.

The state was exactly Phase II's, one rung in: II-1a put W^X in the model and II-1b made the emitter
follow it. This is the II-1b of the device axis.

## 2. The theorem is a **biconditional**, and that is the rung

```
∀ StreamID:  the table binds it  ⟺  an assigned device carries it,  to exactly that domain.
```

`hv_s2::smmu::derive_stream_table` is the derivation; `intended_binding` states independently what
the relation asks for; `stage2_binding_at` reads the emitted bytes back through the architecture's
field definitions. The assertions relate the *second* and the *third*, so a wrong emission and a
wrong expectation cannot agree (design-lesson #36).

A one-directional theorem would have been the weaker rung, because the two halves fail differently
and neither implies the other:

| direction | what it is | what losing it looks like |
|---|---|---|
| **soundness** (⇐) | rung 2's ∀-StreamID default-deny **surviving derivation** | a device reaching memory nothing authorized |
| **completeness** (⇒) | every assignment is **realized** | the proven relation is a decoration — satisfied by a derivation that writes nothing at all |

The completeness half is not decoration itself. A derivation that bound nothing would satisfy
"nothing is bound that should not be" perfectly, and it is exactly the failure ⑦ found in the Verus
`Obs` split (a green proof over a surface that cannot exhibit the flow) and that rung 2's
`binding_one_stream_leaves_every_other_denied` needed a non-vacuity clause to exclude.

### 2a. The premise rung 4a's exclusivity rests on and does not establish

Rung 4a made "two holders for one device" **unrepresentable** — one `Option<DomId>` per device,
never a set — so exclusivity is a property of the *type* with nothing to prove
(`docs/SMMU-DEVICE-ASSIGNMENT.md` §2a). Writing the derivation turned up what that refines to in
hardware, and it is not automatic:

> Model exclusivity becomes **hardware** exclusivity only if the `DevId → StreamID` map is
> **injective**.

Two devices sharing a StreamID share one STE, so whichever is bound last silently decides where
*both* land — one domain's bus master walking another domain's tables, with the model's exclusivity
invariant perfectly satisfied throughout. `derive_stream_table` therefore refuses a non-injective
map (`DeriveError::StreamAliased`), and the refusal is proven. It is unreachable at the metal's
single bus master, which is exactly why it is *proven* rather than *argued*: it is the kind of
premise that goes unstated until a second device arrives.

## 3. The three design calls

### 3a. Where the derivation lives, and what it may know

`hv_s2::smmu`, pure and zero-`unsafe`, the twin of `build_stage2_from_p2m`'s pure half. It takes the
**shipped `hv_core::device::System` itself**, not a transcription of it, so the theorem is about the
relation the model proves rather than about a copy someone keeps in step. The two things it must not
compute are handed to it as data:

```rust
pub fn derive_stream_table(
    words: &mut [u64], log2size: u32,
    devices:    &hv_core::device::System,   // the proven relation
    stream_of:  &[u32],                     // DevId → StreamID
    binding_of: &[Option<Stage2Binding>],   // DomId → its Stage-2 tables + VMID
) -> Result<(), DeriveError>
```

`hv-core` cannot name a StreamID, for the reason it cannot name a physical address (design-lesson
#14e); `hv-s2` is only ever *told* one, so it cannot invent the correspondence either. **The metal
owns exactly one line of it**, `DevId 0 → pcie::stream_id(bdf)` (`edu` at PCIe slot 1 ⇒ StreamID 8),
and it is handed to `install_stream_table` rather than set by a separate call — a stream table that
exists without the map giving its indices meaning should not be constructible.

`binding_of` is written by `stage2::build_stage2_from_p2m` **itself**, not by its callers, from the
`VTTBR_EL2` value the domain's CPU would be given (`vttbr_table` / `vttbr_vmid` — rung 3's proven
seam, `docs/SMMU-TRANSLATION.md` §2b). So *"the device walks the same table as the domain's CPU,
under the same VMID"* still holds by construction, one rung further out.

### 3b. When it re-derives — and why the diff trick does **not** transfer

In `teardown::dispatch`'s post-dispatch funnel, per the module's own transition-agnostic argument —
but **unconditionally, not as a diff**.

The frame scrub diffs because scrubbing is an *action tied to an edge*: a frame that went
allocated → free. It has to watch for that edge or it fires at the wrong time. A stream table is a
**pure function of state**, so re-deriving it after every dispatch is not an optimization to be
justified, it is what makes the table a refinement at all — there is not even an edge to get wrong.
`DeviceAssign`, `DeviceRelease`, `domain_destroy`'s sweep and any device-touching transition a later
arc adds therefore need no arm.

What *is* diffed is the derived **artifact**. The words are compared against the live table and the
hardware is touched only when they differ, which is not a soundness question (equal words mean the
SMMU already holds the right configuration) and buys two things: a boot's worth of unrelated
hypercalls costs no command-queue traffic, and the invalidation stays load-bearing exactly where a
stream really is bound or dropped — so a remove-the-fix probe on `CMD_CFGI_STE` can still go red.

### 3c. A derivation that cannot be represented: fail-**closed**, then fail-**loud**

The pure layer **refuses**, and leaves the table denying **every** stream — not merely the device it
could not represent. All-or-nothing, so the postcondition has two clean arms: `Ok` and the
biconditional holds exactly, or `Err` and nothing reaches memory. A derivation that bound the devices
it *could* express and quietly dropped the rest would leave a table nothing describes.

The metal then publishes the denying table and **halts**. That is the ruling
`build_stage2_from_p2m` already makes for a model state it cannot represent faithfully — whose
predecessor dropped such a frame with a bare `continue`, a silent under-map. Deny alone would be
safe and *silently divergent*: the model says the device belongs to A, the hardware says it reaches
nothing, and nothing ever notices. That is a denial of service which leaves every invariant in the
repository perfectly satisfied, i.e. design-lesson #79's unchecked direction, on a new axis.

### 3d. The guard that was deliberately **not** written

The derivation does not re-check that a device's holder is `Live`, and the metal does not withdraw a
domain's binding when that domain dies. Both are obvious defence-in-depth. Both would **mask the
model's own mechanism**: with either in place, deleting `device::System::release_all_of` from
`domain_destroy` would leave the device denied for the *metal's* reason, and the probe that shows
the proven sweep is load-bearing could not go red.

So the metal **consumes** rung 4a's `assigned ⇒ Live` — proven ∀-values on the shipped code, ∀-size
in Verus, and over every reachable state by the enumerator — instead of duplicating it. That is what
it means for this table to *refine* the relation rather than to run beside it, and it is the
generalization worth keeping: **a redundant guard at the refining layer does not add safety, it
removes the ability to tell which layer is carrying the property.**

## 4. What is proven — `hv-verify::smmu_stream_derivation`

Six Kani harnesses on the shipped `hv_s2` builder and the shipped `hv_core::device` relation.

| harness | what it closes |
|---|---|
| `the_derived_table_binds_exactly_the_assigned_streams` | **the biconditional**, ∀ StreamID and ∀ assignment vector: the entry is exactly what the relation asks for, and permits exactly when it asks |
| `a_swept_holder_leaves_no_stream_bound_and_spares_the_others` | the teardown sweep, in **both** directions — every stream of the dying holder's devices denies, **and** every other holder's device keeps exactly its binding (#79: the over-sweep is the direction no invariant checks) |
| `a_refused_derivation_leaves_the_table_denying_every_stream` | totality, and the fail-closed arm: ∀ input, either the biconditional or nothing reaches memory. Started from a table that already permits, so it cannot pass on storage that was zero all along |
| `a_map_that_aliases_two_devices_onto_one_entry_is_refused` | §2a — the injectivity premise |
| `the_derivation_is_a_function_of_the_relation_alone` | ∀ prior table contents, two derivations from one relation give **identical words** — which is what makes "re-derive after every dispatch" sound: no residue of a previous state can survive |
| `the_refinement_check_is_the_property_and_can_fail` | the predicate the boot asserts over the real 256-entry table is the property, **and** goes false for ∀ StreamID the relation does not authorize the moment that stream is permitted (#71 — a check that cannot fail reads as evidence when it is none) |

**Sized to two devices and two domains, deliberately, and for a different reason than rung 4a's.**
These are *pure builder* harnesses — no `dispatch` seam, so none of `first_cross_violation`'s
O(domains²) cost (design-lesson #79's corollary). The axis Kani unwinds here is the **device count**,
and two is where every property has content: aliasing needs a pair, and "one holder swept, another
spared" needs a pair. `hv_s2::smmu::MAX_PROVEN_DEVICES` is the shared constant `hv-metal` pins
`NUM_DEVICES` against, so a device population proven but not shipped — or shipped but not proven —
is a build error (design-lesson #71(c)).

**There is deliberately no deployed-size derivation harness, and the number is measured.** Rung 2's
deployed-size harness is cheap because `verdict` decodes one word; a *derivation* harness at 256
entries fills the table, writes an STE, and decodes three words at a symbolic StreamID out of a
2048-word array — **265 s at 64 entries, and non-terminating at ten minutes at 256**, against a
whole-suite CI budget of forty-five minutes most of which is already spent. Recorded rather than
quietly dropped, because a bounded axis nobody mentions reads as a covered one. What covers it
instead: the builder is size-generic and every write routes through `bind_stage2` → `bind` →
`entry_offset` (rung 2 proves that size-generically, *and* at `BUS0_LOG2SIZE` for the deny half);
`hv-s2`'s unit tests run the derivation, the sweep and every refusal arm **at `BUS0_LOG2SIZE`**;
`hv-metal` runs `table_refines_the_relation` over the **real 256-entry table** after every
derivation and halts if it disagrees; and the shared constants make "proven at a size that is not
shipped" a build error.

**No Verus mirror, and the ruling has an expiry.** Rung 2 declined one because the stream table has
no unbounded axis Kani cannot close; that holds here. StreamID is closed over all 2³² values, the
table size is pinned to the deployed constant, and the device count is a compile-time constant of
the metal rather than a model-unbounded population — while the ∀-size statement about the *relation*
is already Verus's (`device_assignment_preservation.rs`). The ruling **expires** if the device
population becomes configuration-driven, or if the table becomes 2-level.

## 5. The metal witness — six phases, one boot, and nothing binds anything by hand

Rung 3's witness chose a domain and called `bind_stream_stage2`. Nothing in rung 4b touches the
SMMU. Every entry below is produced by the derivation, from the funnel, as a consequence of a
hypercall issued through the **proven** `Hypervisor::dispatch`.

| phase | the hypercall | required outcome |
|---|---|---|
| 1 — derivation control | `DeviceAssign{dev 0 → A}` | the derived STE names **A's own `VTTBR_EL2` table and VMID**, and the DMA lands where the **table** says, not at the IPA |
| 2 — release | `DeviceRelease{dev 0 from A}` | the table denies **every** StreamID; **aborted**, `C_BAD_STE` |
| 3 — re-permit | `DeviceAssign{dev 0 → A}` | lands again — so phase 2 was a decision |
| 4 — **teardown** | `DomainDestroy{A}` *while A holds it* | **aborted**, `C_BAD_STE`, and A's old landing PA untouched |
| 5 — **rebirth** | `DomainCreate{A}` + fresh tables | still **aborted**, and the **reborn** tenant's memory at that PA intact |
| 6 — re-assign | `DeviceAssign{dev 0 → A}` | lands in the **reborn** domain's frame |

**Phase 1 is the control and it is first** (design-lesson #70), and it is stronger than rung 3's: it
witnesses the *derivation* as well as the translation, because the STE it lands through was never
written by this file. Two sentinels as in rung 3 (#75) — the address the device asked for must be
untouched, and both are seeded and read back.

**Phases 4 and 5 are the isolation content**, and they are the confused deputy in the flavour every
CPU-side proof here is structurally blind to. A stale grant is a capability the reborn tenant would
have to *use*; a stale device assignment is a bus master already pointed at its memory, writing with
no hypercall and no vCPU. The reborn domain re-allocates the **same model frame**, so it is backed by
the same machine frame at the same physical address the dead tenant's device was reaching.

Three supporting decisions are load-bearing enough to name:

**The forbidden sentinel is seeded *after* the destroy, not before.** `domain_destroy` frees A's
frames, and the teardown funnel **scrubs a freed frame** — measured: the old landing PA reads `0x0`
immediately after the destroy (§6). A sentinel written before it would therefore compare zero
against zero, while a landed DMA also writes zero, so the two outcomes would be indistinguishable.
That is a check that could not have failed, and it was the first thing this phase got wrong on
paper.

**Emission must precede assignment, and the ordering is enforced by a halt.** A `DeviceAssign` to a
domain with no registered `Stage2Binding` is `DeriveError::NoBinding` and stops the machine. See §7.

**Phase 6 re-permits into a *different incarnation*.** Every "aborted" above is equally consistent
with a wedged SMMU, and a sequence that only tightens can never tell (#70c) — and here the re-permit
is sharper than rungs 2 and 3's, because the domain it reaches is a fresh tenant with freshly
emitted tables rather than the one that was denied.

## 6. What was probed — twelve mutations, ten red, **two refused**, one measurement

All six phases passed on the first boot, which makes the probe battery more important, not less.

| mutation | result |
|---|---|
| **remove `device::System::release_all_of` from `domain_destroy`** — the headline | **RED, and it is the leak itself**: `p4 denied=false forbidden_after=Some(0)`, `p5 denied=false forbidden_after=Some(0)` — the derived table keeps binding the dead tenant's device, and it **zeroes both the dead tenant's old landing PA and the reborn tenant's memory** |
| the funnel never re-derives (`rederive` returns immediately) | RED — `derived=None`; the STE is never built and phase 1 does not land |
| **re-derive only at the explicit `DeviceAssign`/`DeviceRelease` sites** — the design this rung rejected | **RED** — `DomainDestroy`'s sweep is missed entirely and phases 4 and 5 leak exactly as above. The transition-agnostic funnel is not a tidiness preference; the explicit-sites version is *wrong* |
| derive incrementally: drop the leading `init_deny` | RED — `p2 denied=false`; the released stream's entry survives, which is the residue the *function-of-the-relation-alone* harness excludes |
| drop `CMD_CFGI_STE` from the derivation | RED — `p2 refused=false` (the release does not take: the SMMU serves a cached STE) and phases 4/5 land. Consistent with rung 3 |
| register the **wrong** Stage-2 table for the domain (`s2ttb + 0x1000`) | RED — `derived=Some(0x400c1000)`, `names_a=false`, and the DMA takes `F_TRANSLATION` on the issued IPA |
| the fence crossing names the wrong StreamID (`DevId 0 → sid+1`) | RED — `derived=None`; **every** phase loses its outcome, so the whole result rests on `pcie::stream_id` being the RequesterID the hardware presents (rung 2's sharpest probe, still sharpest) |
| derive the table but never install it | RED — caught by the **boot read-back**: *"the published stream table does NOT refine the model's device assignment"* |
| the same, **plus** blinding the read-back check | RED — the phases catch it independently, so the witness does not rest on the read-back |
| the boot read-back always answers `true` | green **on its own** — correct, and not a gap: with the derivation right there is nothing for it to catch, and the probe above shows it *is* the detector when the install breaks. Its falsifiability is separately established by `the_refinement_check_is_the_property_and_can_fail` and by three `hv-s2` unit tests |
| **drop `CMD_TLBI_NSNH_ALL`** | ⚠️ **nothing red — see below** |
| **the `NoBinding` refusal skips the device instead of refusing** | ⚠️ **nothing red — see below** |

**The measurement that made phase 4 a check rather than a decoration.** After `DomainDestroy`, the
old landing PA reads **`0x0`** — the teardown funnel scrubbed the freed frame. So a forbidden
sentinel seeded *before* the destroy would compare zero against zero, while a landed DMA also writes
zero: the two outcomes would be indistinguishable and the phase could not have failed. Seeding after
the destroy is what makes it discriminate, and the number above is why.

### The two that refused to go red

**1. Removing `CMD_TLBI_NSNH_ALL` still changes nothing — and the hypothesis that phase 5 would
change that was wrong.** Rung 3 recorded this as a declared residual and predicted that a
*rebind-after-teardown* path might make the stage-2 TLB invalidation load-bearing, because that is
where a stale translation would be answerable. Rung 5's phase does exercise exactly that path, and
the probe is still green. So the residual is **inherited unchanged, and the proposed way to close it
is now ruled out**: on this platform `CMD_CFGI_STE` alone is sufficient to make a rebind take (the
previous row shows it is genuinely load-bearing), ~~which is consistent with QEMU dropping the
stream's cached translations along with its configuration~~. The command stays because the
architecture requires it — the same standing as the cache maintenance in `scrub_frame`, which as of
2026-08-08 means *mechanism witnessed on the AEM, this call site not* rather than *reasoned, not
witnessed*. Witnessing it needs a platform that caches stage-2 translations across a
configuration invalidation, i.e. not this one (design-lesson #72).

✅ **THAT LAST SENTENCE NAMED THE INSTRUMENT, AND IT HAS NOW BEEN BUILT** — `fvp-probe` on Arm's
Base RevC AEM, 2026-08-07 (`docs/SMMU-TRANSLATION.md` §5a). Two corrections fall out, and the
struck clause above is the first:

* **`CMD_CFGI_STE` does NOT drop cached translations.** On a platform that caches, a re-pointed STE
  stays shadowed by the cached translation even after `CMD_CFGI_STE`, until the VMID changes or the
  TLB is invalidated. So the guess that QEMU drops translations along with configuration is not what
  is happening; **QEMU simply caches nothing**, and the two are indistinguishable there.
* **`CMD_TLBI_*` is load-bearing wherever caching exists** — change a descriptor without it and the
  old frame is still returned; issue it and the new one is.

⚠ The residual's own wording is **still accurate and still stands**: this is not boot-witnessed.
`hv-metal` runs on QEMU, and `fvp-probe` is a separate program sharing none of its code. What
changed is that the command is now known to be *code whose effect QEMU cannot exhibit*, rather than
code of unknown value.

**2. The `NoBinding` refusal is unreachable in this boot, and is kept anyway.** Making it skip the
device instead of halting changes nothing observable, because `stage2::build_stage2_from_p2m`
registers a domain's binding at emission and the witness always emits before it assigns. That is a
fact about *this boot's ordering*, not about the derivation — a controller that assigned a device to
a domain whose image had not been emitted would reach it immediately. The guard is kept and the
residual declared, exactly as rung 4a kept its masked mint gate: a refusal that depends on another
subsystem's ordering staying arranged as it is has no teeth of its own. §7 records what a
guest-driven control domain would have to do instead.

## 7. What rung 4b does **not** claim

* **A `DeviceAssign` to a domain with no emitted Stage-2 image halts the machine.** Today the only
  "controller" is the metal itself, which emits before it assigns, so the halt is a build-order
  assertion. A hypervisor with a guest-driven control domain would have to *refuse the hypercall*
  instead — which needs the model to know something about the metal's emission state, a seam this
  rung deliberately does not open. Declared, not closed.
* **One device, one StreamID** — unchanged from rung 3. QEMU's `edu` is the only bus master in the
  machine, so `StreamAliased`, and the sweep's "spare the other holder" direction, are proven but
  not boot-witnessed.
* **The two consumers are still not simultaneous.** The device is driven while no vCPU of that
  domain is running — unchanged from rung 3 §6, and now the arc's remaining item is integration
  rather than diamond.
* **The VMID field and the stage-2 TLBI are still not boot-witnessed on QEMU.** Rung 3's two
  refusing probes (`docs/SMMU-TRANSLATION.md` §5) are inherited verbatim — and rung 3's *hypothesis*
  that a rebind-after-teardown path would make `CMD_TLBI_NSNH_ALL` load-bearing is now **ruled out**:
  phase 5 exercises exactly that path and the probe is still green (§6).
* **The derivation trusts `assigned ⇒ Live`.** By design — see §3d. It is proven in rung 4a at three
  layers, and re-checking it at the refining layer would destroy the arc's headline probe.

---

*See also: `hv-s2/src/smmu.rs` (`derive_stream_table`, `intended_binding`,
`table_refines_the_relation`), `hv-verify/src/lib.rs` `smmu_stream_derivation` (the proofs),
`hv-metal/src/smmu.rs` (`rederive`, `register_domain_binding`, the fence crossing),
`hv-metal/src/teardown.rs` (the funnel), `hv-metal/src/dmawitness.rs` (`rung4`),
`hv-metal/boot-test.sh` (the markers), `docs/SMMU-DEVICE-ASSIGNMENT.md` (the relation this refines)
and `docs/SMMU-TRANSLATION.md` (the binding it derives).*
