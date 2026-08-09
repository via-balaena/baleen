# M5 Arc 5 — content non-inheritance: the metal's half of "a reborn tenant inherits nothing"

**Status:** done. `hv-core` / `hv-hal` / `hv-s2` untouched.

> **Three later corrections, recorded here so this page is not read as the final word.**
> 1. **Arc 6a** exposed that `scrub_frame` was **span-blind** — it always addressed the base window
>    and zeroed 4 KiB, so this arc's claim was **false for superpages**. Fixed in PR #54; see
>    `docs/ARC6A-SPAN-REFINEMENT.md` and the seam note below.
> 2. **Arc 6b-pre** moved the scrub from the *allocate* to the *free*. See §2.
> 3. ★ **2026-08-08, PR #168 — the cache-maintenance derivation this page shipped was WRONG, and in
>    the direction that leaks.** It argued only that a dirty line could be evicted *after* the
>    zeroing, and concluded a trailing `dc civac` was the fix. But `DC CIVAC` **cleans before it
>    invalidates**, so the trailing pass wrote the dead tenant's still-live dirty line back *over* the
>    zeroing: the maintenance meant to prevent a resurrection performed one. Fixed by
>    `civac → zero → civac`. See §"Cache maintenance" below — the derivation now lives with the code,
>    not here.

`hv-core` proves a reborn slot inherits no **authority** — no grant, no port, no owned frame
(design-lesson #15's inbound-reference sweep, live on the metal since M5 Arc 0). It says nothing
about **bytes**, and it never can: `Mfn` is an opaque token by design, the same fence that abstracts
the guest-physical→machine map and 512-slot tables (#14e). Content non-inheritance is therefore an
obligation the fence assigns **downward**, and it sat in the deferral ledger as
*"frame-content scrubbing on reuse."*

**The gap was real.** Removing the scrub reproduces it in one boot: the reborn tenant reads the dead
tenant's bytes verbatim off the re-allocated machine frame (§4, row 1).

---

## 1. The statement audit: the ledger named ONE of three channels

Enumerating everything a guest can write that outlives a `DomainDestroy` (#37):

| channel | reachable by the next tenant? | status before | closed by |
|---|---|---|---|
| model data frames | **yes** — the machine frame is a pure function of the `Mfn` | leaking | `stage2::scrub_frame` at allocate |
| **CoW disk overlay** | **yes** | `discard_overlay` existed since Arc 4 but was wired to **no** teardown path — its only caller was an explicit step in the thesis terminal | `teardown::on_destroy` |
| **virtio device state** | **partly** — `status`/`queue_ready`/`interrupt_status` read straight back; stale queue addresses survive but fail closed behind `backend_authorize`'s grant check | never reset since boot | `teardown::on_destroy` |
| guest code image | no — RO+X in Stage-2, no guest can write it | not a channel | — |
| `GuestContext` | no | re-seeded, but only as fixture hygiene in the two phases that use it | — |
| bump heap | no — mapped into no Stage-2 | never reclaims; holds every destroyed domain's model state until reboot | **not closed — recorded** |

The heap is secrets-at-rest inside the *trusted* layer, not a cross-tenant channel. Named so it is a
decision on record rather than a later discovery.

---

## 2. The seam — and why the intuitive one depends on a detail nobody would state

The obvious design is *"scrub when a frame's owner changes."* Whether that works turns entirely on
**when you sample the owner**. Both variants were built and booted; they disagree.

`hv-core` deliberately has no generation counter (an unbounded incarnation would break the
enumerator's finite-state BFS, #15b), so **domain IDs are reused** — a reborn tenant occupies the
slot under the *same* `DomId`.

- Sampling **at reachability time** — the natural, cheap place, since Stage-2 emission already walks
  every frame — is **defeated**: it compares `Some(1)` with `Some(1)` across a destroy/rebirth, never
  observes the `None` the free passed through, and scrubs nothing. *Measured: the secret came back.*
- Sampling **after every transition** works, because it catches that intermediate `None`.
  *Measured: no leak.*

So the honest statement is not "owner-diff is wrong" but **"an owner-diff is only sound at a sampling
rate that already costs more than the alternative."**

**What this arc did** was key on the transition that *creates* ownership — `p2m::allocate`, the sole
place a frame becomes `Frame::Allocated` from `Free`, so complete by construction with no ownership
history kept.

> **Superseded by Arc 6b-pre: the scrub now hooks the FREE, not the allocate.** A frame must pass
> through `Free` between owners, so the two are equally complete hooks — but free is better on every
> axis that later came up. It leaves nothing at rest (discharging residual 1 below rather than
> carrying it); it does not erase a real guest's pre-loaded payload, which is deposited into guest
> RAM *before* the hypervisor runs and which scrub-at-allocate would have zeroed the moment the model
> config was built; and it costs nothing at boot. The hook is also transition-agnostic now — the
> funnel diffs allocation state against its own shadow and scrubs whatever went allocated → free, so
> bulk `free_all`, explicit frees, and any future freeing transition are covered without a new arm.
> See `hv-metal/src/teardown.rs`. **Choosing allocate was the wrong side of the pair, and it took the
> requirements of the *next* arc to show it (design-lesson #43).**

---

## 3. A funnel alone would be prose across N sites — so it is checked

Routing every dispatch through `teardown::dispatch` puts the obligation in one place, but *"every
site remembered to use the funnel"* is exactly the shape M5 Arc 4 spent an arc removing. So the
scrub has a **second, independent derivation** (#36): `build_stage2_from_p2m` — a different code
path, reached when a frame becomes **reachable** rather than **owned** — asserts every frame it is
about to map was scrubbed since it was allocated, and halts otherwise. A dispatch that bypasses the
funnel does not silently leak; it stops the machine (§4, row 3).

## Cache maintenance: required, ORDER-SENSITIVE, and witnessed on a model that caches

**The derivation is not repeated here.** It lives on `scrub_frame` in `hv-metal/src/stage2.rs`,
which is the only copy that a reader can check against the instruction sequence it describes. This
page kept a second copy from Arc 6b-pre (PR #55, the last commit to touch this file) until
2026-08-09, and the second copy is what stayed wrong after the code was fixed — so what follows is
the standing, not the argument.

* **Required**, and ⚠ **the reason CHANGED under ledger 5's A2 while the requirement did not.** It
  used to be that EL2's stores were non-cacheable (MMU-off, `SCTLR_EL2.C = 0` under A1) while the
  dying guest wrote through cacheable EL1 mappings, so the zeroing could not touch the dead tenant's
  dirty lines. **A2 made EL2's stores cacheable too** — the guest windows are inside `L1[1]`, which
  A2 maps Normal-WB Inner Shareable, the same memory type `hv-s2` gives the guest. EL2 and the dying
  tenant are now in one coherency domain, so the zeroing *does* reach the tenant's lines. The
  maintenance is still required, for the other observer: a **bus master** reading the frame is not
  inner-shareable, so the zeroing must be pushed to the point of coherency.
* **Order-sensitive, and this page originally got the order wrong** — see correction 3 at the top.
  The maintenance runs **before** the zeroing (which is what erases the tenant) and again after.
  ⚠ **The after-pass is no longer a no-op**: it was one while EL2's own stores were non-cacheable,
  and A2 is exactly the rung that made it load-bearing — it is what pushes the *zeroing itself* out
  to the point of coherency. The instruction sequence is unchanged; #168 wrote it in its A2 shape
  before A2 existed.
* **No longer "reasoned, not witnessed."** `fvp-probe` milestone 3 established that Arm's AEM does
  withhold a dirty line from a non-cacheable observer, and milestone 4 reproduced this exact
  sequence on it and measured the secret surviving the shipped order and erased by the current one.
  ⚠ **The witness is the PROBE's, not this code's** — `fvp-probe` shares no source with `hv-metal`,
  and `hv-metal` has never run on the FVP. The mechanism is witnessed; this call site is not.
* **Still invisible to every gate this repo owns.** QEMU/TCG models no cache, so no boot test here
  can distinguish the right order from the wrong one — §4 row 4 measured exactly that, and it is why
  the defect survived to 2026-08-08 with every gate green throughout.

---

## 4. Mutation table — run, recorded, including the rows that do not fire

| # | Mutation | Result |
|---|---|---|
| 1 | **Remove the scrub** (the pre-arc state) | **LEAK REPRODUCED** — `lifecycle content LEAK: the reborn slot read the dead tenant's bytes: D3ADTENANT-must-not-survive-rebirth`; forbidden marker fired |
| 2a | Owner-diff sampled **at reachability time** | **LEAK REPRODUCED** — the DomId-reuse trap, exactly as §2 predicts |
| 2b | Owner-diff sampled **after every transition** | **STILL GREEN** — works; this is what corrected the claim from "owner-diff is wrong" to "only at a costlier sampling rate" |
| 3 | **Bypass the funnel** (`expect` dispatches directly) | **CAUGHT** — the independent Stage-2-time check halts. *(Under 6b-pre the check compares the model's allocation state against the funnel's shadow rather than a per-frame scrubbed flag; same #36 shape, same catch.)* |
| 4 | Remove the `dc civac` cache maintenance | **STILL GREEN — does not fire.** Predicted: TCG models no cache. ⚠ **This row measures the PLATFORM, and it was over-read.** It was recorded as evidence for a "reasoned, not witnessed" label; what it actually shows is that no gate here can grade this code *at all* — which is why the order being wrong (correction 3) also went undetected. The instrument that can grade it is `fvp-probe`, not this table |
| 5 | Remove the `scrubbed` shadow re-sync | **STILL GREEN — does not fire** |
| 5b | Funnel bypass **and** no re-sync (the combination it should defend) | **CAUGHT anyway** — so the re-sync is not load-bearing on any path this fixture builds, either |
| 6 | Remove the CoW overlay discard | **CAUGHT** — `THESIS TEST FAILED` (`overlay_gone=false`) |
| 7 | Remove the virtio device reset | **CAUGHT** — `THESIS TEST FAILED` (`device_state_reset=false`) |

**Row 2b is the one that changed the design writeup.** My first attempt at mutating my own claim was
mis-constructed — it sampled per dispatch, i.e. tested the variant that *works* — and came back
green. That is what surfaced the overstatement. A mutation that fails to reproduce your own criticism
is evidence about the criticism, not a nuisance.

**Rows 5 and 5b are the honest #39 result.** The shadow re-sync fires nowhere, including in the
combination it was written to defend. It is kept — it is two lines and it covers a free→reallocate
cycle *within* a phase with the funnel bypassed, which this fixture does not build — but it is
recorded as unexercised rather than presented as load-bearing.

**Witnesses, and why read-before-write is the whole point.** The pre-arc fixture had the reborn guest
write its sentinel *before* reading, so its own read-back was fresh regardless — which is exactly how
this leak sat in the ledger with every boot green. The new witness reads first. boot-test: **131 →
135 checks**, both feature configs.

---

## 5. Residual

1. ~~**The scrub is eager at allocate, not at free.**~~ **DISCHARGED by Arc 6b-pre** — the scrub
   moved to the free, so the bytes are gone at the tenant boundary rather than sitting in DRAM until
   the next allocate. Scrubbed-at-rest is now what is delivered.
2. ~~**The cache-maintenance half is reasoned, not witnessed**, and cannot be witnessed under TCG
   (§4 row 4).~~ **RESTATED 2026-08-09 — the "cannot be witnessed" half was false, and believing it
   is what let the order stay wrong.** It cannot be witnessed *under TCG*; it was witnessed on Arm's
   AEM within an hour of anyone building the instrument (`fvp-probe` m3/m4, PRs #167/#168).
   **What remains true:** the witness is the probe's and not this code's — `hv-metal` has never run
   on the FVP — so the mechanism is witnessed and this call site is not. It still rides on the
   standing crate-wide EL2-MMU real-hardware gap.
3. **The bump heap is not scrubbed and never reclaims.** Not guest-reachable, so not a channel —
   but a destroyed domain's model state stays resident until reboot.
4. ~~**`CACHE_LINE` is a conservative constant (64), not a `CTR_EL0` read.** Too-small is always safe
   (it merely repeats `dc civac` within a line); too-large would skip lines, so this must stay a
   floor if it is ever made dynamic.~~ **DISCHARGED by PR #169** — the stride measures
   `CTR_EL0.DminLine` and takes `min(64, 4 << DminLine)`, so it can only get *finer* than the old
   constant, and the "must stay a floor" condition this residual named is the shape of the fix.
   ⚠ It was `stage2::scrub_line_bytes()` when #169 landed; **A2 moved it to
   `hv-metal/src/cache.rs`'s `line_bytes()`**, where four maintenance loops share it instead of one —
   naming the function here would be a pointer that has already moved once.
   Measured 64 on both platforms this project runs on (QEMU `virt` and the AEM), so it is
   behaviour-neutral where observed.
5. **The completeness argument for the seam is an audit fact, not a machine-checked one**: "`allocate`
   is the sole owner-creating transition" was established by reading `hv-core/src/p2m.rs`, exactly
   the transition-list-completeness residual the Stage-2 program already carries.
6. **DMA is out of scope entirely** — no SMMU/IOMMU work exists yet, so a device could in principle
   read a frame the CPU path scrubs. Named, unclosed, and unchanged by this arc.
