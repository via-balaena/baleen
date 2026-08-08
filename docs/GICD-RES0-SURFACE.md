<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# ⑲ — a conforming guest was being killed for a legal read

*The last of ③-b1's three declared residues, and the one whose declaration turned out to understate*
*itself. Read §1 even if nothing else: the defect is small, the shape it came in is not.*

---

## 1. The defect: a three-way answer returned as an `Option`

`GICD_CTLR.ARE_NS` is forced on by this model, and the architecture then makes the distributor's
copies of INTIDs 0..31 **RES0** — they are banked per redistributor, and reads of the distributor's
copies return zero. ⚠ *Asserted from the architecture, not measured here* (`docs/QEMU-AND-METAL.md`
§5's column discipline).

The model's bank decode returned `Option<usize>`, and its `None` meant **two different things**:

| the offset is… | `dist_word_index` | what the caller did |
|---|---|---|
| a word of SPI state | `Some(w)` | serve it |
| a **redistributor-banked copy** — RES0 here | `None` | **refuse → RETIRE THE GUEST** |
| not a word of this bank at all | `None` | refuse → retire the guest |

The caller's policy is right for the third row — since the retire rung, a register this model does
not have stops the guest, because a silently-ignored write leaves a guest believing something took
effect. It is **wrong for the second**, and nothing distinguished them.

★ **The reusable shape: an `Option` from a decode is a two-way answer, and a decode with three cases
will quietly borrow one of them.** The tell is a caller that gives `None` a *policy* meaning — here
"retire" — which can only be correct for one of the things `None` stood for. The repair is
`DistWord { Spi(w), BankedRes0, Elsewhere }`.

## 2. The declaration understated itself, and that is the second finding

`gicv3.rs`'s residue list said pending/active, and named **four** registers. MEASURED on the deployed
shape, **ten** offsets refused a conforming read and so retired the guest:

```
GICD_IGROUPR0  GICD_ISENABLER0  GICD_ICENABLER0  GICD_ISPENDR0  GICD_ICPENDR0
GICD_ISACTIVER0  GICD_ICACTIVER0  GICD_ICFGR0  GICD_ICFGR1  GICD_IPRIORITYR bytes 0..31
```

`IGROUPR0`, `ISENABLER0` and `IPRIORITYR0` are not pending/active state at all — they were never in
the declaration. ★ **A declaration that understates its own scope is worse than no declaration**,
because it is read as an inventory. This one had been read that way for three arcs.

## 3. What changed, and what deliberately did not

Reads of the banked copies return **zero**; writes are **ignored** — accepted and applied to nothing.
Every change is `refuse → answer`, never the reverse.

⚠ **`GICD_SGIR` is RES0 under `ARE_NS` too and stays REFUSED, on purpose.** It is an *action*
register: silently ignoring a write drops an interrupt the guest believes it sent, which is worse
than a loud refusal. The RES0 treatment covers the **state** copies only. That boundary — state
copies read zero, action registers stay loud — is the actual decision in this rung; the code change
is mechanical.

`GICD_ITARGETSR` is likewise RES0 under `ARE_NS` and likewise still refused: the model has no arrays
for it, has never recognised it, and a guest using GICv2 targeting under affinity routing is doing
something the model should be loud about.

## 4. Evidence, and its honest ceiling

**There is no guest witness, and none is available.** MEASURED: `/dev/mem` exists in the guest
(`crw------- 1,1`) but busybox has no `devmem` applet, and `dd if=/dev/mem` over the GIC window
returns **`Bad address`** — the read is refused by the kernel and never reaches EL2. The shipped
kernel touches none of these registers either, which is why the defect survived three arcs. So the
∀-offset evidence is **Kani's**, exactly as ⑱-2 established for this surface (*"every property below
is invisible to the boot gate and the proofs are the whole of the evidence"*).

Beside it, a boot-side count — EL2 sweeping its own model, in the shape `mmu.rs`'s page sweep took:

```
baleen: gicdsurface OK: of 16384 word offsets in dom 1's GICD frame, 414 are answered
and 15970 RETIRE the guest — and all 17 redistributor-banked RES0 copies read ZERO
```

★ **That first number is new information nobody had.** "A register this model does not have retires
the guest" was policy; **15,970 of 16,384 word offsets** is its size. The verdict carries the counts
because a predicate over a set that collapsed passes vacuously (design-lesson #214).

### 4a. The kill probes, and what they refuted

MEASURED, five probes × four harnesses:

| probe | reads-zero | write-inert | still-refuses | partition |
|---|---|---|---|---|
| **P0** unmodified — the CONTROL | PASS | PASS | PASS | PASS |
| **P1** `dist_banked_res0` always false (pre-⑲) | **RED** | PASS | PASS | PASS |
| **P2** `dist_banked_res0` always true | PASS | PASS | **RED** | PASS |
| **P3** no banked exclusion at all (the `ARE_NS` aliasing bug) | **RED** | PASS | PASS | PASS |
| **P4** `ICFGR` as 1 bit/INTID, so `ICFGR1` is not RES0 | **RED** | PASS | PASS | PASS |

⚠ **The `write-inert` column is killed by nothing, and that refuted what its own doc claimed.** The
harness said it was what stops `GICD_ISENABLER0` writes reaching a guest's PPI enables. P3 restores
exactly that historical bug and the harness still passes — because ⑱-2 gave each redistributor its
own bank, and `is_enabled` reads *that* for INTIDs 0..31. The distributor's word 0 is **write-only
dead storage**. The **storage split** carries that property; the decode never did. The doc now says
so (design-lesson #222: a guard you believe is backed up is where to look for a single point of
failure — and here it was the reverse, a guard claiming credit for something else's work).

⚠ **P4 is not hypothetical.** `ICFGR` is two bits per INTID, so INTIDs 0..31 span words 0 **and** 1 —
and this model's decode shipped with only word 0 excluded once already, leaving `GICD_ICFGR1`
aliasing `GICR_ICFGR1`. The same off-by-one in the RES0 set retires a conforming guest on exactly one
register.

## 5. What this rung does **not** claim

* **Not conformance.** Ten offsets stopped killing a guest that reads them; the model still answers a
  small measured subset of a GICv3 distributor and refuses the rest by design. ⑯'s ceiling stands:
  the harnesses prove **structure**, not GICv3 conformance.
* **Pending/active state is still not modelled** — the other half of this residue. SPI reads return
  zero, which is wrong for a guest that polls them, and remains declared rather than half-built.
* **No guest has ever read one of these registers on this machine**, before or after. The rung makes
  a *class* of guest work that could not have; it changes nothing for the shipped one.

---

*See also: `hv-vdev/src/gicv3.rs` (`DistWord`, `dist_banked_res0`, and the residue list this closes),
`hv-verify/src/lib.rs` H4d (the harnesses, the independently-derived RES0 predicate, and the measured
probe matrix), `hv-metal/src/vgic.rs` (`survey_gicd`, `banked_res0_read_zero`).*
