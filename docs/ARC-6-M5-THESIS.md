<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# M5 Arc 6 — the thesis assembled (the finale)

The capstone of the metal build: the isolation thesis, live, composing the proven arcs into
non-interference. A control domain (`dom0`) spawns a no-net **vault** holding an un-forgeable secret and
a **disposable** (a CoW overlay on the shared RO template). The vault is a live *modeled* domain that
owns its secret but is not scheduled (only the disposable executes); its secret provably cannot reach the
disposable, and the disposable is destroyed clean leaving the vault + template pristine. "The audit IS the
arc" — the deliverable is `docs/AUDIT-3-NON-INTERFERENCE.md`, witnessed by this scenario. `hv-core`/
`hv-hal` untouched (this composes; no new isolation *mechanism*).

## What it composes

- **Arc 2 (concurrent inter-domain isolation):** the vault and disposable each run in their own
  **distinct-VMID Stage-2**; a frame is a leaf only in its owner's tables (the owner filter), so the
  vault's secret is simply **not present** in the disposable's Stage-2. The disposable probes it → a
  hardware **translation fault**. This is the empirical non-interference.
- **Arc 0 (dynamic lifecycle):** `dom0` **destroys** the disposable through the proven teardown
  (`revoke_grants_to` + `free_all`) — clean shell afterward, and a **reborn** disposable inherits no
  reach to the vault (a `p2m_link` of the secret is refused `Unauthorized`).
- **Arc 4 (CoW template):** the disposable's disk is a CoW **overlay** on the shared RO template; on
  teardown the overlay is **discarded** and the **template is pristine** — a model-level re-assertion of
  the Arc-4 immutability property (the disposable's divergence is HV-seeded here; the guest-driven CoW
  proof is Arc 4's).

## The new content

Not a new isolation mechanism — the **scenario** and the **audit**:
1. The vault/disposable scenario wired through the real `Hypervisor::dispatch` (`setup_thesis_model`).
2. The **non-interference witness**: the disposable's probe of the vault secret faults, and the secret's
   token `V4ULTSEC` is a `FORBIDDEN_MARKER` (it reaches the console only if the probe read it).
3. The **channel enumeration** (`finish_thesis_test`): HV-side and **exhaustive** over the model's `⇝`
   seams — no grant reaching either domain (`any_grant_to`), no event channel (`no_evtchn_between`), no
   foreign page-table link (`has_foreign_link_into`), no control edge (`controls`) — `¬(vault ⇝ disposable)`.
4. The **Tier-D bridge**: the metal establishes that precondition; the model's ∀-N non-interference
   theorem (`¬(b ⇝ a) ⟹ obs(a)` unchanged) gives the conclusion. The headline (the disposable can't *read*
   the secret) is the confidentiality dual, demonstrated empirically; scoped honestly in Audit #3.

## Witnesses (boot-test-asserted, the thesis in one boot)

| witness | marker |
| --- | --- |
| the disposable's authorized write works; its probe read nothing | `thesis: disposable wrote+read its own frame … obtained nothing` |
| non-interference (empirical) | `thesis non-interference OK: … probe of the vault secret -> translation fault` |
| channel enumeration (exhaustive → Tier-D) | `thesis channel enumeration: no grant, no event channel, no shared page-table link, no control edge …` |
| reborn inherits nothing | `thesis reborn OK: a reborn disposable could NOT link the vault's secret` |
| the whole thesis | `THESIS TEST PASSED — the vault's secret never reached the disposable …` |
| the secret never crosses | `FORBIDDEN_MARKERS` absent: `V4ULTSEC` |

## Scope and honesty

- **Synthetic un-forgeable guests** (the vault's secret is seeded HV-side through `GuestMemory`; the
  disposable cannot guess or reach it). No dependency on real Linux — the thesis survives the
  kernel-gated 5e capstone, which was the whole reason Linux was sequenced last.
- **Information-flow non-interference over the isolation surface** — the two Tier-D granularity
  exclusions (timing / pCPU-occupancy, and authority) carry over and are stated in Audit #3.
- Runs last in the boot, composing every prior arc; each phase rebuilds a fresh `Hypervisor`.
