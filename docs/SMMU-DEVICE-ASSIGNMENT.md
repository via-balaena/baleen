# SMMU rung 4a — device assignment in the model

*The SMMU arc, rung 4a. Rung 1 (PR #91) closed the pre-enable DMA window; rung 2 (#92) made the*
*answer to an unbound bus master **no**; rung 3 (#93) confined a bound one to a domain's proven*
*`p2m`. All three are **metal configuration**: the model knows nothing about bus masters, so nothing*
*proves a device belongs to one domain, or that it stops reaching memory when that domain dies.*
*This rung is the relation the stream table will refine — `p2m` → Stage-2, one level out.*

---

## 1. What rung 3 left open, precisely

`docs/SMMU-TRANSLATION.md` §6 says it in one line: *"No `hv-core` model of DMA. Device→domain
assignment is metal configuration; the model knows nothing about bus masters, so there is no ∀-N
statement that a device is assigned to at most one domain, and no hypercall by which a guest could
ask for one."*

That is not a gap in the hardware story — the metal genuinely confines a bound device — but in what
stands *behind* the binding. `bind_stream_stage2` is called by hand in a witness; nothing says which
device should be bound to which domain, or when it must stop being bound. So the three questions
with ∀-N content were all unasked:

* is a device assigned to **at most one live domain**?
* is assignment **swept on `DomainDestroy`**, so a dead domain's device cannot keep DMA-ing?
* can a domain **learn** a device's assignment without holding it?

Rung 4a answers all three in `hv-core`. Rung 4b derives the stream table from the answer.

## 2. What a device is — ownership-shaped, not consent-shaped

`DevId` follows the `Mfn` precedent exactly: an opaque index, a system-wide relation, and the
token→hardware map (`DevId` → BDF → StreamID) below the fence. The core never learns what a
StreamID is, for the same reason it never learns what a machine frame address is (design-lesson
#14e), and that is what lets one proven relation serve an SMMU, an x86 IOMMU, or a fixed device
tree.

**The alternative was a grant.** A grant is the right shape when two principals must agree about
something *one of them owns*; no domain owns a device. Modelling assignment as consent would need an
invented owner, a two-step offer/accept protocol, and a second kind of inbound reference to sweep —
all to express a sharing the hardware cannot represent anyway: one STE, one `S2TTB`. **The
refinement target is exclusive, so the relation is exclusive**, and assignment is a capability
handed *down* the authority axis (Xen's `XEN_DOMCTL_assign_device`, a domctl about a target) rather
than across between peers.

### 2a. Exclusivity is unrepresentable, not checked

"At most one domain per device" is **not an invariant of this rung**. The state is `Option<DomId>`
per device, not a set, so a second simultaneous holder cannot be written down — the same move III-1
made for the pending-interrupt overflow. A method returning "no device has two holders" could never
return `false`, and a check that cannot fail reads as evidence when it is none (#71). It is stated
here rather than proven anywhere, on purpose.

What *does* need proof is the coupling to the lifecycle, because that one can break.

## 3. The invariant: `assigned ⇒ Live`, and why it is #15 again

An assignment is a bare `DomId` recorded in a table that is **not the domain's own**, which outlives
the transition that wrote it and is honoured later by whoever occupies that slot. That is the exact
shape of a grant naming a grantee and a half-open port awaiting a peer — so it is kept standing the
same way (design-lesson #15), and needed **no new mechanism**:

| half | mechanism | reused verbatim? |
|---|---|---|
| mint gate | `reject_dead_target(to)` in `device_assign` | yes — the existing helper |
| teardown sweep | `device::System::release_all_of(target)` in `domain_destroy` | new, 6 lines |
| standing check | the device clause of `CrossViolation::DeadDomainReferenced` | extended, not added |

The violation variant is **extended rather than duplicated**: `DeadDomainReferenced` already means
"nothing inbound names a `Dead` slot", and a device is a third kind of inbound reference, not a new
property. The disjunction moved into a named predicate, `is_unreferenced`, so a fourth kind has an
obvious home instead of a fourth invariant — and its outbound twin `is_clean_shell` stayed exactly
as it was.

**Why it matters more than the other two kinds.** A stale grant or a stale port is a capability the
reborn tenant would have to *use*. A stale device assignment is a **bus master already pointed at
its memory**, writing with no hypercall and no vCPU. It is the confused deputy in the one flavour
every CPU-side invariant in the repository is structurally blind to.

## 4. The two transitions, and the one asymmetry worth naming

```
DeviceAssign  { dev, to }    controls[caller][to]                    — no self-exemption
DeviceRelease { dev, from }  caller == from || controls[caller][from] — self-permitted
```

**`DeviceAssign` is the only whole-domain operation here with no `caller == target` exemption**, and
the difference is not fussiness. Every other self-permitted control op (`DomainDestroy`,
`SchedSetAffinity`) only ever spends or narrows what the caller already holds. Assignment does the
opposite twice over: it takes a **system-wide exclusive resource**, and it creates an **inbound-DMA
authority over the assignee's own memory**. Neither is something a domain may hand itself, for the
same reason `may_create` cannot be self-granted — authority must have a provenance.

Release keeps the exemption because it only ever *removes* an authority. Taking needs an authority
above you; giving back needs only being you.

### 4a. Why both calls name their counterparty

`DeviceRelease` takes `from` rather than looking the holder up, and that is a **disclosure decision
made before the code was written**, not ergonomics. Naming it lets the authority gate be settled
*before* the device table is read, so a caller with no claim on `from` is refused without learning
whether `dev` is held at all. The same discipline as `domain_destroy`'s gate ordering, applied to a
new namespace.

## 5. Is assignment observable to a non-holder? — decided, then machine-checked

Yes, narrowly, and it is **recorded in `obs⁺` rather than argued away**. What survives the gate
ordering above:

* any domain holding *some* control edge can learn each device's **free/taken bit** (`Busy`);
* holder **identity** leaks only along control edges;
* a domain controlling nothing is refused at the gate and learns **nothing at all**.

This is ⑥/F1's repair (record the disclosure), not ⑥/F4's (partition the resource), and the reason
the two cases differ is worth stating. `sched::run`'s `PcpuBusy` reads *which domain* occupies a
pCPU — an identity `obs⁺` could only carry by declaring the whole schedule public, so ⑥ partitioned
instead. `DeviceAssign`'s `Busy` reads something `obs⁺` can carry **in full and exactly**, so
recording it is the complete repair rather than a declaration standing in for one.

The honest reading: **Baleen's device namespace is free/taken-public to any domain holding a control
edge** — a declared disclosure beside the public domid namespace, and strictly narrower than it.

### 5a. The observable has three arms, and each is forced

```
0        unassigned
1        held by a domain the observer neither is nor controls   (holder NOT named)
2 + h    held by h, where h is the observer or a domain it controls
```

A two-valued free/taken bit **does not work**, and the depth-independent test
`the_device_busy_guard_is_observed` is the witness: two states in which the device is taken — once
by a domain the observer controls, once by a stranger — are `obs⁺`-equal under that projection, yet
take the *same* hypercall to `Ok` (idempotent re-assignment) and to `Busy`. Naming the holder in the
third arm is forced for the same reason at finer grain: the observer may assign to any of several
domains it controls.

Equally, the holder in arm `1` is deliberately **not** named. No outcome of any call the observer
can issue distinguishes one uncontrolled holder from another, so recording it would
over-approximate the observable exactly as ②′-(a)'s raw frame owner did.

## 6. What is proven

| layer | statement | where |
|---|---|---|
| ∀-values, shipped code, bounded device count | `assign`/`release` are **total**, a refusal writes nothing, an assignment moves **exactly one** device, and the sweep takes **exactly** the holder's devices — over every prior assignment vector | Kani `hv-verify::device_assignment` (6 harnesses) |
| ∀-size, arbitrary device population | `holder(dev) == Some(d) ⇒ d Live` preserved by every transition class; the sweep exact in both directions; the boot state satisfies it | Verus `device_assignment_preservation.rs` (6 verified) |
| ∀ reachable state, real `Hypervisor` | no reachable interleaving of assign/release/create/destroy leaves a `Dead` slot with a device — and the destroy sweep is **reached** | `hv-sim::enumerate` (`device_assignment_preserves_the_invariants`, `..._saturates`, `the_destroy_sweep_has_real_work_to_do`) |
| non-interference, integrity | a device changing hands moves only the gaining/losing domain's `obs`, and every transition that can do so is authorized by an **existing** channel — **no new `Channels` term** | `hv-sim::noninterference` + Verus `noninterference_instantiation.rs` (`local_respect_holds`) |
| non-interference, confidentiality | the exclusivity guard's disclosure is a function of `obs⁺` | both, `step_consistent_holds` |

Two of those deserve a sentence each.

**Kani and Verus divide the axes, and neither subsumes the other.** Kani makes the whole assignment
vector symbolic on the *shipped* `hv_core::device` code but must bound the device count (2); Verus
quantifies over a `Seq` of arbitrary length but over a mirror. The headline "∀-N" is exactly their
conjunction plus the enumerator's real-code sweep — the framing the ledger has used since the
2026-07-26 review.

**The sweep is proven exact in *both* directions**, and the second is the one nothing else would
catch. Too little and a bus master outlives its holder; too much and destroying one domain silently
disarms every other domain's devices — a denial of service that leaves every invariant perfectly
satisfied. `sweep_is_exact`'s second conclusion is the only thing in the repository that would
notice.

## 7. What the probing found

Eight remove-the-fix mutations on the model, three on the Verus preservation proof, three on the
Verus instantiation. **Fourteen went red; two refused, and both are findings rather than passes**
(design-lesson #72).

| mutation | result |
|---|---|
| remove the `DomainDestroy` device sweep | 3 red — the ∀-N sweep, the direct lifecycle test, and the sweep-reached test |
| remove the sweep **and** the device disjunct from `is_unreferenced` | ∀-N sweep goes **green**; only the direct tests fail — so the disjunct is exactly what gives the ∀-N result its teeth |
| permit self-assignment | 1 red, the policy test — and **only** that, since a self-assigned device breaks no invariant |
| `assign` overwrites instead of refusing `Busy` | 2 red |
| `device_release` reads the device table before settling authority | 1 red — the gate-ordering test |
| `release_all_of` clears every device | 4 red |
| drop the assignment relation from the enumerator's state fingerprint | 1 red — the non-vacuity check (device ops reach no new states) |
| **remove the mint gate `reject_dead_target(to)`** | ⚠️ **nothing red** — see below |
| Verus: drop `live(to)` from `assign_preserves` / drop `sweeps_holder` from `destroy_preserves` / make the sweep clear everything | all 3 reject |
| Verus NI: blind the device view to a taken/free bit / empty `peer_live` | both reject |
| **Verus NI: drop the device sweep from the `Destroy` cascade** | ⚠️ **still verifies — correctly**, see below |

### The mint gate is masked, and is kept anyway

`reject_dead_target(to)` in `device_assign` **cannot fire today**: the authority gate already
requires `controls[caller][to]`, and a control edge requires a live target
(`ControlEdgeDeadEndpoint`). Removing it changes nothing observable.

It stays, and the reason is not belt-and-braces. *"An assignment names a live domain"* is a property
of assignment; that it currently follows from how authority happens to be gated is a fact about a
different subsystem's invariant. A guard that depends on another invariant staying arranged as it is
has no teeth of its own — so the guard is kept, the residual is declared, and the ∀-N lemma
(`assign_preserves`) takes `live(to)` as a hypothesis it genuinely uses.

### The NI probe that refuses is asking a different question

Removing the device sweep from the Verus `Destroy` cascade leaves all 20 obligations green. That is
correct: the sweep's content is the *safety* invariant "no device names a dead domain", which
`device_assignment_preservation.rs` owns (dropping it there **does** reject), and a surviving
assignment moves no observation the cascade had not already moved. The sweep is modeled in the NI
file for fidelity — had it opened a channel, that is where it would have had to be accounted for.

### The finding: `ObsPlus` had drifted from the bridge

Writing the NI carriers turned up something the analogy would not have. The Verus instantiation's
`obs⁺` was **missing the peer-liveness component** the real-code bridge has carried since ⑥/F1 — and
had been for two arcs. Nothing noticed, because every earlier guard that reads a third domain's
liveness (`DomainCreate`'s `¬live[target]`) writes a component *no third observer carries*, so the
divergence was invisible. `DeviceAssign` is the first modeled transition whose **outcome is visible
in every domain's observation** — a device becoming assigned changes the device view for all of them
— so the omission finally bit.

The composition was sound throughout; the surface was narrower than the bridge's and the two had
silently drifted apart. That is ⑦'s finding in the other direction, and it is the argument for
writing carriers rather than reasoning by analogy: `DeviceRelease` really *is* `SetAffinity`'s shape,
and saying so in prose would have been exactly the move GAP-C existed to stamp out.

## 8. What rung 4a does **not** claim

* **Nothing on the metal changes.** `hv-metal` gains one constant (`NUM_DEVICES = 1`) and no
  behaviour. Assignment is now a proven relation with **no consumer** — deliberately, and exactly as
  Phase II-1a landed W^X in the model before II-1b made the emitter follow it.
* **It says who holds a device, never what memory that device reaches.** Reachability is already a
  proven relation (`p2m` → `hv-s2`'s leaf map); restating it on the device axis would be a second
  copy to keep in step. The composition — *a device assigned to `d` walks `d`'s Stage-2 tables* — is
  rung 4b's refinement obligation.
* **No guest drives it.** The transitions are swept, fuzzed and proven, but no boot assigns a device
  through them yet. Behaviour-nil by design, and the same standing as the model's executable-leaf
  bit after II-1a.
* **The device namespace is public to controllers**, per §5 — declared, recorded in `obs⁺`, and not
  closed. Closing it means mediating the namespace, the same program declined for domids.

---

*See also: `hv-core/src/device.rs` (the relation), `hv-core/src/hypervisor.rs` (the two transitions,
the gate ordering, the sweep, `is_unreferenced`), `hv-verify/src/lib.rs` `device_assignment` (the
Kani harnesses), `hv-verify/verus/device_assignment_preservation.rs` (∀-size preservation),
`hv-verify/verus/noninterference_instantiation.rs` (the Tier-D carriers),
`hv-sim/src/enumerate.rs` + `hv-sim/src/noninterference.rs` (the real-code sweeps), and
`docs/SMMU-TRANSLATION.md` §6 for what this rung was written against.*
