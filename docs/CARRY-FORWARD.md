# Carry-forward — what this project learned that outlives it

**Baleen is paused as a project and complete as research.** This document is the part meant to
travel: the things that *did not* close here, turned into advice for whoever builds the next
mixed-criticality system — specifically on **seL4 + Microkit + libvmm**, which is the substrate
[`CONSUMER-CORTENFORGE.md`](CONSUMER-CORTENFORGE.md)'s consumer chose over this one.

⚠ **This is not a summary of what Baleen proved.** That is the root [`README.md`](../README.md) and
the documents indexed in [`README.md`](README.md). This is the residue — the open items, the
corrections, and the two places the project was wrong about itself — because a parked project's
failures are worth more to a successor than its results are.

★ **The framing that makes this useful:** Baleen was a from-scratch AArch64 separation kernel with
five assurance tiers over it. Choosing a verified kernel instead removes some of these problems
outright and relocates others. **The relocated ones are the point.** Each section below says which
it is.

---

## ⚠ About the figures in this document

Every number here is a **2026-08-14 snapshot**, and none of it is gated from this file. Each is
regenerable:

| figure | regenerate with |
|---|---|
| crate line counts, harnesses per subsystem | `docs/assurance-data.json` (`cargo xtask site-data`) |
| Kani harnesses, Verus obligations, sweeps, proof-to-code ratio | `cargo xtask doc-counts` |
| boot markers | `cargo xtask doc-markers` |

**No argument below depends on an exact value** — they are all ratios and directions, and they are
cited so a reader can check that the direction is still true. A number in an ungated document is
gated, deleted, or rotting; these are marked rotting deliberately, because deleting them would
make the arguments unfalsifiable.

---

## 1. It broke on time, not on space — and that is the one requirement still open on the new stack

**What happened here.** Baleen's memory isolation held throughout its life. Every serious failure
was temporal.

- **EL2 owned no clock.** Re-entry to the hypervisor was caused only by the *guest* — a trap it took,
  or the arch-timer it programmed for itself. Sound with one guest. **False with two:** a guest
  switched in while idle sat in `wfi` waiting on a deadline EL2 never armed, EL2 got no tick, and
  **the peer never ran again — the whole machine dead.** It reached `main`, made a *required* CI job
  time out post-merge (its own PR run was green), and reproduced locally at **2 runs in 15**. The
  structural fix was EL2 taking its own `CNTHP_*_EL2` deadline, which the guest cannot program, mask
  or outlast.
- **The scheduling policy's work-conservation property was flatly false.** One pinned vCPU stopped
  every domain permanently: **0 transitions over 200 ticks, with every mechanism invariant holding.**
  Full account in [`CASE-STUDY-WORK-CONSERVATION.md`](CASE-STUDY-WORK-CONSERVATION.md).

**What it teaches.** In a partitioning system, spatial isolation is the property that gets the
attention and temporal isolation is the property that fails. Both defects above were invisible to
every memory-safety argument in the repository, and both were fatal to the whole machine rather than
to one partition.

**On seL4 + Microkit + libvmm.** This is exactly **seL4 MCS** territory — scheduling contexts, i.e.
capability-based access to CPU time with enforced budgets. Two things to carry in:

- **Use MCS from the start**, not the classic scheduler. Retrofitting a temporal-isolation story is
  what this project spent its worst week on.
- ⚠⚠ **MCS functional correctness is proved on RISC-V. The Arm 64-bit port is in progress** (DARPA
  PROVERS). So on AArch64 you get MCS as *shipping code*, not as *proof*. **This is the only exo
  requirement that is genuinely open anywhere in the field** — carry it as a named open item in the
  safety case rather than as a footnote, and write the budget-overrun witness yourself on the board.

**Relocated, not removed.**

---

## 2. A safety invariant does not see liveness

**What happened here.** Every theorem in this repository is satisfied by a machine that runs nothing.
The work-conservation defect passed five assurance tiers because all five were checking safety
properties and the defect was a liveness property. The honest ledger had even called the gap
"defensible — a policy has no safety invariant; the mechanism beneath it *is* proven." That
reassurance was wrong, and the failure mode was not unfairness but a total permanent stall.

**What it teaches.** "It cannot corrupt the layer beneath it" is not a substitute for "it works."

**On the new stack.** seL4's three verified properties — functional correctness, integrity,
confidentiality — are **all safety properties**. Adopting a verified kernel buys a proof about
spatial isolation and **nothing at all** about a control loop meeting its deadline. For a device
worn by a person, the deadline *is* the safety property. That evidence is yours to produce, and it
will be measurement rather than proof.

**Relocated, not removed** — and this is the one most likely to be mistaken for removed.

---

## 3. A latency bound must be derived, or declared unproven — never fitted

**What happened here.** The scheduler's latency bound was **published false**, corrected, then
derived, across four PRs. The instructive part is the middle step. The ad-hoc bound was **sound on
all 75 measured rows and tight on 45 of them** — and was *still provably the wrong shape*, because
the policy ranks by `service/weight` and is therefore scale-invariant, while the quantity the formula
was built from doubles under that same scaling. **A formula that matches all of your data can be
structurally incapable of being the true bound.**

The derived replacement is sound on the same 75 rows and **tight on only 29** — strictly looser than
the ad-hoc form it replaced. That was the right trade and is recorded as such, so nobody "improves"
it back: an unproven formula of a provably impossible shape is worse than a proven loose one.

⛔ Also established: the remaining gap is **not reachable by a bigger harness**. A claim about
unbounded runs is not bounded-depth, and a claim about a limit is not a finite check. Knowing which
of your properties are out of reach of your tools — *before* investing in the tools — is the lesson.

**On the new stack.** The number a safety monitor budgets against is worst-case response time.
**Measure it with margin and state it as measured.** For the theory, the ground is already taken:
**Virtual Timeline** (Liu, Rieg, Shao, Gu *et al.*, POPL 2020) is the formal abstraction for verified
preemptive scheduling with temporal isolation, and the classic weighted-round-robin / Deficit Round
Robin results cover the quantitative case. Read rather than re-derive.

⚠ One more residual worth inheriting: this project's monitor **observes and cannot act** — a
detector, not an intervener. For an exoskeleton that is the wrong shape, and the design question
("what may a monitor *do* to a partition, and what proves that safe?") should be answered early
rather than discovered late.

**Relocated, not removed.**

---

## 4. The trusted layer grew larger than the verified one — and the fix was to measure purity

**What happened here, the bad half.** After a deliberate, sustained campaign to push logic upward out
of the hardware layer, the split finished at:

| | lines | `forbid(unsafe_code)` | Kani | Verus | fuzz |
|---|---|---|---|---|---|
| the five fenced crates | **12,499** | ✅ | ✅ | ✅ | ✅ |
| `hv-metal` | **12,964** | ⛔ | ⛔ | ⛔ | ⛔ |

**The unverified layer ended up larger than the verified core**, and it is where every guest-reachable
halt lived. The repository deliberately refuses to claim there are none left, because the audit that
found eight of them undercounted and missed a ninth — *an audit that undercounted once is not
evidence of completeness the second time.*

**What happened here, the good half — and this is the most directly reusable technique in the
project.** The guest's device surface looked like the hardest thing to verify. It was **measured**
instead of assumed: the vGIC and PL011 *models* contained zero `unsafe`, zero MMIO and zero `asm!`.
They were lifted into `hv-vdev` — 939 lines, `forbid(unsafe_code)`, reachable by the prover — leaving
a thinner adapter behind in the metal. Those models now carry **56 of the project's Kani harnesses,
the largest single block in the corpus.**

**The device *protocol* is verifiable. The register poke is a genuinely thin seam.** They only look
like one thing because they live in the same file.

**On the new stack.** Choosing a verified kernel does not dissolve this — it **relocates** it.
The kernel is verified; libvmm, your drivers, your monitor, and your Microkit system description are
not. Everything you write sits outside the proof. Three moves:

- **Microkit protection domains are the natural fence.** Push logic into pure, host-testable,
  no-`unsafe` PDs and keep the driver PD as thin as *measurement* says it can be.
- **`#![forbid(unsafe_code)]` on day one.** This project ran for weeks on the belief that its pure
  crates were pure, enforced by nothing — a `grep` said zero, and **a convention is not a gate**.
  `forbid` (not `deny`) makes it a build error no inner `allow` can silence.
- **Microkit is Rust** (and `rust-sel4` is live), so none of this costs the language.

**Relocated, not removed.**

---

## 5. Verify per-architecture, per-board, per-component — the headline is never the claim

**What happened here.** This project published a field map of related work and **found eight defects
in it within one day, every one from a repository or paper nobody had opened.** Rows were built from
surveys, papers and search snippets; the primary sources disagreed. The three that bear directly on
the new stack:

| what the headline says | what the primary source says |
|---|---|
| "seL4 is verified" | Verification is **not uniform across architectures**. On **AArch64** — the one most people ship on — there is functional correctness and integrity, but **no confidentiality proof and no binary correctness**. ARM 32-bit has all four. |
| "seL4 has temporal isolation" | MCS functional correctness is proved on **RISC-V**; the Arm 64-bit port is **in progress**. |
| "libvmm boots Linux guests on Arm" | True, but **GICv3 emulation is per-platform** and a live discussion item rather than a settled feature. **Confirm it for your specific board.** |

**What it teaches.** ★★ Two rules came out of it, and they generalise past this field:

1. **A row citing a PAPER is safe; a row about whether a PROJECT IS ALIVE is not.** A paper's result
   is permanent — its artifact is not. Three of the projects on the map are **proved-and-unbuildable**.
   Answer *"is this ground taken?"* and *"can I build on this?"* separately; a single status chip
   cannot express both, and collapsing them is how the first version misled.
2. ⚠⚠ **A date implies verification. Where there was none, the date was rigour-shaped decoration** —
   it looks exactly like the discipline while being its absence. Several rows said "checked
   2026-08-13" when the truth was "found via search on 2026-08-13".

**On the new stack.** "seL4 is verified" is a secondary-source claim that dissolves into
per-configuration detail, and **the detail is where a safety argument lives**. Never write it into
one without the architecture qualifier.

**Removed as a Baleen problem, sharpened as a general one** — the more mature the ecosystem you
adopt, the more its headline compresses.

---

## 6. Do not add up your assurance tiers

**What happened here.** Five tiers — exhaustive enumeration, Kani, Verus, fuzzing, boot witnesses —
and the one real defect sat in the gap between them. The case study's title is the finding:
**"Every tier was green. Only two were looking."**

**What it teaches.** This is settled literature, not a local discovery. **Knight & Leveson (1986)**
showed 27 independently written program versions failing in correlated ways far above chance;
**Littlewood & Wright** model dependence between a *testing* leg and a *formal verification* leg
specifically. ⛔ **A verification portfolio is not the union of its tiers.**

**On the new stack.** You will have kernel proofs, your own tests, and possibly Kani over your Rust
PDs. Ask per-property — *which tier is actually looking at this?* — and expect the answer to be
"none" more often than feels comfortable.

**Relocated, not removed.** More tiers is a different property from more coverage.

---

## 7. Check that revocation actually bites

**What happened here.** The metal emits its Stage-2 tables **once**. Ending a grant therefore never
touched the already-emitted descriptors, and **a monitor's read survived revocation** of the grant
that authorised it. Convenient for the arc that found it; a latent surprise for anything that expects
revoking access to remove access.

**What it teaches.** For every operation whose name promises removal, write the **negative witness** —
the test that the thing is genuinely gone — rather than trusting the API's name.

**On the new stack.** seL4 capability revocation is a first-class, verified operation, and this is a
genuine argument *for* the stack. Still write the witness on your board: the guarantee you are
inheriting is about the kernel's capability tables, not about whatever your VMM cached.

**Largely removed** — but the habit transfers to everything you build on top.

---

## 8. QEMU is not the platform

**What happened here.** Baleen never left the emulator, and the residuals show exactly what that
costs. On real Arm silicon, stage-2 translations **are** cached and `CMD_TLBI_*` **is** load-bearing;
this was witnessed on Arm's AEM by a separate probe. **On QEMU nothing is cached**, so the repository
ships TLBI code whose effect its own gate platform cannot exhibit. The VMID field, the stage-2 TLBI
and `CNTVOFF_EL2` are all "not boot-witnessed" for the same reason. See
[`QEMU-AND-METAL.md`](QEMU-AND-METAL.md) before believing any sentence in this repository containing
the word "metal".

⚠ The comparison that stings, and it is the honest one: **a dormant project that ran on real silicon
in production beats an active one that never left the emulator**, for anyone choosing a substrate.

**On the new stack.** Buy the board before designing the system, and **pick a board the kernel
actually supports** rather than one it merely boots on. `board-probe/` in this repository is built,
self-testing, and **has never run on a board** — the probe-the-platform-before-designing-against-it
discipline is what to carry over, not the code.

⚠ **This also changes which board.** Any hardware recommendation made for *Baleen on silicon* selects
different hardware than *the exo platform*: the first optimises for avoiding a vGIC rewrite, the
second requires an seL4-supported platform. **Decide which goal you are buying for before buying.**

**Relocated, not removed.**

---

## 9. Nothing gates a document, and long non-blocking verification needs a signal that changes shape

Two smaller process findings, both of which cost real time here.

**The prose goes stale under the code, and no gate sees it.** Three consecutive PRs corrected a
latency bound and **none updated the prose describing it**, leaving the published artifacts telling
readers a formula "has not been derived" two PRs after it was. The standing "read the full diff
before every push" rule was followed on all three and could not have caught it — the changed code was
a test *body*, and the contradicting documentation sat *above* it, so the contradiction never
appeared in any diff. ★ **The action that does catch it is a different action, not a more careful
diff read: after changing what a thing DOES, re-read the nearest prose that says what it IS.**

**A badge habituates.** A scheduled verification workflow was **red for two weeks** with its status
badge visible at the top of the repository's front page the entire time. Green and red occupy the
same pixels in the same place and the eye stops resolving it. ⛔ "Put the signal where it will be
seen" has been tried and failed. What worked was a **new element appearing** — an issue count going
0 → 1, which persists until closed.

**Fully transferable.** Neither has anything to do with hypervisors.

---

## ⛔ What does NOT transfer

**Do not import this project's constraint set along with its lessons.** Single-pCPU, two
compile-time guests, no toolstack, no dynamic configuration — those are consequences of writing a
kernel from scratch in four weeks, not insights. seL4 simply does not have them, and treating them
as inherited requirements would be the worst possible reading of this document.

Likewise: this project's **0.53:1 proof-to-code ratio** is not a benchmark to hit. It is low because
its proofs are bounded-size checks plus a mirror, against seL4's reported ~20:1 for a refinement
chain reaching C and, on ARM 32-bit, the binary. **Different classes of claim.** A ratio is not a
quality.

---

## ★ The one asset that transfers whole

Not a technique — a discipline. **The honest ledger**: stated residuals, refuted hypotheses kept in
place rather than deleted, corrections recorded beside what they corrected, every claim carrying what
it does *not* cover.

Two reasons it is worth starting on day one of the next system:

- **It is what found nearly everything.** Every defect of *meaning* in this project — a stale claim,
  a sentence gone false under a new configuration, a count printed but never asserted — was caught by
  a human reading a diff or interrogating a ledger item, and **none by a green gate**. The gates check
  structure. The ledger is what makes the interrogation possible, because it records what was left
  open in the words of the person who left it open.
- **The certification markets that pay for assurance buy exactly this.** DO-178C, ISO 26262,
  IEC 61508, IEC 62304 and Common Criteria buyers pay for an evidence package an auditor will sign —
  traceability, stated residuals, refuted alternatives — **not for harness counts.** ⚠ The mapping is
  not automatic, and it is where the money is.

★★ **And it cannot be produced retroactively.** Starting a ledger at commit one is free; reconstructing
one from a finished system is not possible, because the thing it records is what you believed *at the
time* and were later proved wrong about.
