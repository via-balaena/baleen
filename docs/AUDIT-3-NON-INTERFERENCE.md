<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Architecture Audit #3 — non-interference: the thesis, bridged to Tier-D

This is the finale, and "the audit IS the arc" (design-lesson #25): the deliverable of M5 Arc 6 is the
**non-interference argument** itself, witnessed by a metal scenario that composes the proven arcs. A
control domain (`dom0`) runs a **vault** holding an un-forgeable secret alongside a **disposable**; the
audit shows the vault's secret **cannot reach the disposable**, and bridges that to the model-level
**Tier-D non-interference theorem** (`docs/TIER-D-NONINTERFERENCE.md`). The audited code is the thesis
phase in `hv-metal/src/guest.rs` (`setup_thesis_model` / `begin_thesis_phase` / `finish_thesis_test`).
`hv-core`/`hv-hal` are untouched (this refines).

## The charter

> The vault holds a secret. The disposable runs alongside it. There must be **no information flow** from
> the vault to the disposable: no channel — memory, grant, or event — carries the secret, and the
> disposable, running to completion and then destroyed, cannot obtain or affect it.

## Two arguments, composed

### (A) Empirical — the disposable tries and cannot (composes Arc 2)

The vault owns its secret frame in its **own distinct-VMID Stage-2**; the disposable owns a disjoint set
of frames in its own. Because `build_stage2_from_p2m` emits a leaf only for a frame the domain **owns**
(the owner filter, Audit #4), the vault's secret is **not present** in the disposable's Stage-2. The
disposable actively **probes** the secret's IPA and takes a **hardware translation fault** (`DFSC=0x07`)
— it never obtains the bytes. The register it would have read (`x2`) stays `0`, never the secret; the
secret's token (`V4ULTSEC`) is a `FORBIDDEN_MARKER` that reaches the console only if the probe read it.

### (B) By construction — no authorized channel exists (the enumeration → Tier-D)

The empirical fault shows the *memory* channel is closed. The audit closes **every** channel by
enumerating them HV-side, against the proven `hv-core` state — **exhaustively** (whole-table queries, not
hand-picked frames) and in both directions:

| channel (model `⇝` term) | thesis check (real `hv-core` accessor) | result |
| --- | --- | --- |
| **consent (grant)** | `!grant().any_grant_to(disp)` **and** `!grant().any_grant_to(vault)` | no grant reaches either domain |
| **signal (event channel)** | `no_evtchn_between(vault, disp)` — scans `any_unbound_into` + every port's `state_of` for an `Interdomain`/`Unbound` referencing the other | no port between them |
| **shared page-table link** | `!p2m().has_foreign_link_into(vault)` **and** `!…(disp)` | no cross-domain leaf/node |
| **authority (control)** | `!controls(vault, disp)` **and** `!controls(disp, vault)` | neither peer controls the other |

These are exactly the model's cross-domain seam relations (consent / signal / control / creation).
`dom0`'s **creation** authority over both is the trusted control domain (the TCB), not a peer channel;
`teardown_reach` is vacuous with no third domain. No authorizing edge connects the vault and the
disposable — `¬(vault ⇝ disposable)`.

## The bridge to Tier-D

The model's **Tier-D non-interference** result (Goguen–Meseguer / Rushby unwinding theorem, proven ∀-N
in Verus, both directions — integrity and confidentiality; `docs/TIER-D-NONINTERFERENCE.md`, PR #19) is:

> `¬(b ⇝ a)  ⟹  obs(a)` is unchanged by any step of `b`,

where `b ⇝ a` is the union of the three seam relationships (grant / evtchn / control+creation) and
`obs(a)` is `a`'s isolation surface (its owned frames+refs, held mappings, grant rows, ports, vCPUs,
edges, liveness). The load-bearing thesis of Tier-D is that **each seam invariant IS the guard on one
channel** — so "no authorizing edge" is exactly `¬(b ⇝ a)`.

The metal scenario establishes precisely that **precondition** for the concrete pair
(`b = vault`, `a = disposable`): the enumeration above is `¬(vault ⇝ disposable)`. The Tier-D theorem —
proven for *arbitrary* configurations and steps — then yields the conclusion: nothing the vault does
changes the disposable's observation, and (the other direction) nothing the disposable does — up to and
including its destruction — changes the vault's. The metal does not re-prove non-interference; it
**instantiates** the precondition, with a hardware fault as the concrete witness that the abstract "no
channel" is real silicon behaviour.

**Honest scoping of what is proven vs. demonstrated.** Tier-D's ∀-N Verus-discharged headline is the
**integrity** direction (`¬(b ⇝ a) ⟹` `b` cannot *affect* `obs(a)`); its **confidentiality** dual
(`a` cannot *read* `b`'s secret) is *characterized* in the Tier-D write-up, following from the same
channel closure, rather than being the separately Verus-discharged lemma. The metal scenario's headline —
the disposable cannot *read* the vault's secret — is the confidentiality dual, demonstrated empirically
(the hardware fault) on top of the same `¬(vault ⇝ disposable)` the integrity theorem consumes. The
**destroy** direction (a step of the disposable leaves `obs(vault)` unchanged) is the integrity direction
proper. So: the *storage-channel* isolation is real and witnessed; the universal ∀-N guarantee is the
model's, and this is a faithful concrete instance of its precondition — not a re-proof, and not a claim
that timing channels are closed (the Tier-D timing/pCPU-occupancy exclusion carries over, below).

Two granularity exclusions carry over from the Tier-D definition and are honest here too: **timing**
(global pCPU occupancy — a covert channel the model abstracts) and **authority** (a domain's power over
others — Tier-C's subject, and here dom0's alone). The claim is information-flow non-interference over the
isolation surface, not a timing-channel-free guarantee.

## The lifecycle half — destroyed clean (composes Arc 0 + Arc 4)

Non-interference must survive the disposable's whole life, including its end. `dom0` destroys the
disposable through the **proven teardown** (`DomainDestroy` — `revoke_grants_to` + `free_all`): afterwards
it is `Dead` and owns none of its frames (clean shell, Arc 0), its CoW **overlay is discarded** (the real
dirty bit clears), and the vault's secret reads back **untouched** (HV-side, through `GuestMemory`). The
shared CoW template stays **pristine** — a model-level re-assertion of the Arc-4 immutability property
(here the disposable's overlay divergence is HV-seeded; the guest-driven trap-and-emulate CoW proof is
Arc 4's — this arc re-cashes the *result* on the lifecycle, it does not re-prove it on the backend path).
A **reborn** disposable in the same slot still cannot reach the secret — a `p2m_link` of the vault's frame
is refused `Unauthorized` (no inherited authority, Arc 0). Teardown is a step of the disposable that
leaves `obs(vault)` unchanged: the destroy (integrity) direction of non-interference, live.

## Verdict

**SOUND — non-interference holds, and the bridge to Tier-D is faithful.** The vault's secret cannot reach
the disposable: the memory channel is closed by hardware (the probe faults), and the audit's enumeration
shows no grant, no shared mapping, and no event channel — i.e. `¬(vault ⇝ disposable)` — so the proven
Tier-D theorem gives non-interference. The disposable is destroyed clean, leaving the vault + template
pristine and a reborn slot with no inherited reach. This is the whole metal build's thesis, cashed.

## Review pass — three spec-blind auditors + empirical mutation testing

Three auditors reviewed the committed thesis on orthogonal axes, spec-blind. **All three: SOUND, no
soundness defect** — and, crucially for a *thesis* arc, two of them converged on a set of **overclaims**
(the code checked less than the prose asserted), all of which were folded into the review-pass commit.

- **unsafe / asm / composition.** Verified the disposable asm (the probe register is guaranteed stale-`0`
  — `mov x4,#0` before the faulting `ldr`, plus a syndrome-independent `ELR+=4` — so a non-fault would
  leave the *real* secret there and be caught), the frame layout/offsets, the fault routing (a stale
  `ACTIVE_VIRTIO` is irrelevant — the discriminator is a pure address test), the per-incarnation
  `FAULT_DFSC` reset, and the `blk.rs` helpers. Empirically confirmed by a clean boot.
- **false-green / witness integrity.** Could not manufacture a hollow green. The headline is a
  **load-bearing triple witness** — the hardware fault record + a probe-value assertion *calibrated* to
  the true leak value + the `V4ULTSEC` FORBIDDEN token — empirically verified: forcing the Stage-2 owner
  filter off (mapping the secret into the disposable) fired **all three** guards (token on the console,
  `faulted` false, `pos_ok` false); no positive marker survived.
- **model-refinement vs ACTUAL hv-core + the Tier-D bridge.** Confirmed the teardown, the `Unauthorized`
  reborn refusal (the p2m↔grant foreign-link seam), and the translation-fault witness all faithfully
  drive/read the proven core; `hv-core`/`hv-hal` untouched. Flagged the overclaims below.

### Overclaims found and fixed (folded into the review-pass commit)

- **The enumeration is now real, not frame-specialized.** The original check tested `authorizes` on two
  hand-picked frames and asserted event-channel absence in a comment. It now queries the whole `hv-core`
  state: `grant().any_grant_to` (both domains), `no_evtchn_between` (scans `any_unbound_into` + every
  port's `state_of`), `p2m().has_foreign_link_into` (both), and `controls` (both) — every seam term of the
  model's `⇝`, exhaustively. *Mutation confirms:* granting the vault's **root** frame (not the secret) to
  the disposable — a channel the old two-frame check would have **missed** — now makes `no_channel` false
  and the thesis FAIL.
- **The Tier-D bridge is scoped honestly** — the metal demonstrates the *confidentiality dual* (storage
  channel) empirically and establishes the `¬(vault ⇝ disposable)` precondition of the model's ∀-N
  theorem; it does not re-prove non-interference, and the timing exclusion is stated.
- **The prose no longer oversells.** "the vault runs alongside" → the vault is a *live modeled* domain
  that owns its secret but is not scheduled (only the disposable executes); "CoW template pristine
  (Arc 4)" → a *model-level re-assertion* (the guest-driven CoW proof is Arc 4's).

### Empirical mutation testing (each caught; each reverted)

| mutation | breaks | caught by |
| --- | --- | --- |
| **secret-crosses** — force the Stage-2 owner filter off so the disposable maps the secret | non-interference | `V4ULTSEC` FORBIDDEN token on console + `faulted=false` + `pos_ok=false` → FAIL (3 channels) |
| **channel-authorized** — grant the vault's root frame to the disposable | the enumeration's completeness | `any_grant_to(disp)` true → `no_channel=false` → FAIL (the *old* two-frame check missed this) |
| **template-mutated** — skip `discard_overlay` / write the template | the lifecycle half | `overlay_gone`/`template_pristine` false → FAIL |

**Review-pass verdict: SOUND, no soundness defect; the claims now match what the code checks. The metal
build's thesis is cashed — and honestly scoped.**
