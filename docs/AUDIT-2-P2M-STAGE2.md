<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Architecture Audit #2 — the `p2m` → Stage-2 refinement

*The centerpiece of M4 Arc 5, and the first point where the ∀-N model proofs make contact with real
hardware **isolation**. Audit #1 asked whether the metal honors the southbound trait *fence*; Audit
#2 asks the isolation question: when the metal translates the proven `p2m` into real AArch64 Stage-2
page tables, does the emitted table **deny exactly what the model forbids — no more, no less** — for
CPU data access? The refinement is realized in `hv-metal/src/stage2.rs` (the builder + the realized
`GuestMemory`) and exercised by the negative-isolation test in `hv-metal/src/guest.rs`. QEMU is a
**sound oracle** for exactly this — Stage-2 translation + fault semantics for CPU-initiated accesses
(`docs/QEMU-AND-METAL.md`: the single most valuable test QEMU can run).*

## The charter — no more, no less

The `p2m` proofs (Tiers A–D) say the model **enforces isolation**: a domain cannot reach another
domain's memory without a grant. That is a claim about the model. On the metal, a guest's reachable
memory is precisely its Stage-2 mappings. So two properties must both hold for the proof to mean
anything about running code:

1. **No less (no isolation hole — not *under*-restrictive).** Every access the model **forbids** must
   **fault**. If a frame the guest may not reach were mapped, the hardware would silently permit what
   the proof forbids — the proof would be a fiction at the seam.
2. **No more (no liveness hole — not *over*-restrictive).** Every access the model **permits** must
   **succeed**. If a frame the guest is authorized to reach were left unmapped, the guest could not
   run its own authorized workload — a different, equally real bug (the model says "allowed"; the
   metal says "fault").

The diamond is the **positive + negative pair**: the table permits exactly what the model authorizes
*and* denies exactly what it does not.

## The refinement relation

The `p2m` models *reachability + permission*: a domain `G` may access machine frame `m` iff `m` is a
**leaf-mapped child** in a page table `G` owns — freely for its own frames, and for a *foreign*
frame only because `hv-core`'s `p2m_link` seam already required a matching **grant**
(`p2m::System::link_edges` surfaces every such edge, with its `writable`/`leaf` bits). The Stage-2
image is a pure function of exactly that relation (`stage2::build_stage2_from_p2m`):

> **Stage-2(G) maps IPA(m) → PA(m) at S2AP π  ⟺  `m` is a leaf child of a table `G` owns, at
> permission π.** A *writable* leaf → `S2AP=RW`; a *read-only* leaf → `S2AP=RO`; a foreign leaf is
> present **only** because a grant authorized it (the seam refused it otherwise); a frame that is
> neither → **no descriptor** → the access faults.

**The metal's `Mfn` → IPA convention (named).** The model's `Mfn` is an abstract frame index with no
linear address, and its page-table *slots* are not linear addresses (the model gives them no
address arithmetic — `TABLE_SLOTS = 8`, abstract). So the refinement is over the model's
**reachability + permission relation** (which frames, at what access), and the metal assigns each
frame a canonical guest IPA (`frame_ipa(m) = DATA_IPA_BASE + m·4 KiB`) backed at a real host PA
(`frame_pa(m)`), with **IPA ≠ PA** so the emitted table performs a genuine translation rather than an
identity pass-through. There is nothing in the model's slot indices to "preserve"; the honest object
of the refinement is the frame-reachability relation, and that is what is realized and audited.

**Honest scope — what the Stage-2 refinement does and does not cover.** The model's leaves are a
guest's *Stage-1* page-table entries in the paravirtual worldview. On this HVM/Stage-2 metal we
**reinterpret the same authorize/deny relation as Stage-2 reachability**, because the proven property
is layer-agnostic (reachability + permission) and Stage-2 is how the metal enforces it for an
*unmodified* guest. Consequences, stated plainly:

- The model's **interior-node sharing** (a foreign edge to a page-table *node*, sharing a whole
  subtree — `p2m`'s transitive-consent mechanism) is a **Stage-1** concept: it is about a guest
  building shared *page tables*, not about which machine frames it may reach. It is **out of scope**
  for a Stage-2 *data-access* refinement, and Arc 5 refines only **leaf-level frame reachability**.
- **Superpages** (a leaf above `L1` — a 2 MiB/1 GiB mapping) are the *same* reachability relation at
  coarser granularity. The builder emits a 2 MiB block for the guest-image region already, so the
  block-descriptor path is exercised; a *model-driven* superpage leaf and its runtime witness are
  **deferred** (see Findings) — no isolation content is lost, only a granularity dimension of the
  runtime witness.

## The test configuration (driven through the real model)

`setup_model` drives the proven `Hypervisor::dispatch` into this configuration — so the Stage-2 the
metal emits is a translation of state the **proven transitions** produced, not a hand-built table:

- dom0 (boot control domain) creates guest `G` = dom1 and peer `P` = dom2.
- `G` allocates `Mfn 1` (its `L1` page table), `Mfn 2`, `Mfn 3`; pins `Mfn 1` as `PageTable(L1)`.
- `P` allocates `Mfn 4`, `Mfn 5`; grants `Mfn 4` to `G` **read-write**.
- `G` links leaves into its `L1` table: `Mfn 2` (writable), `Mfn 3` (read-only), `Mfn 4` (writable,
  foreign — authorized by the grant at the `p2m`↔grant seam).
- `Mfn 5` (P owns) is never granted; `Mfn 6` is never allocated.

## Per-dimension verdict — model vs. emitted table vs. QEMU

Each row: what the **model** authorizes, what the **emitted** descriptor is, and what **QEMU** did
when the guest probed it. The QEMU column is the running third oracle; the fault values are decoded
from `ESR_EL2`/`HPFAR_EL2` and printed only when they match the expected class (a witness produced by
the mechanism).

| dimension | frame / IPA | model says | emitted descriptor | QEMU (running) | verdict |
|---|---|---|---|---|---|
| **write (own)** | `Mfn 2` / `0x8000_2000` | reachable RW (writable leaf) | `S2AP=RW`, XN, Normal-WB | guest writes `0xBEEF`, reads it back; HV confirms via `GuestMemory` | ✅ permits |
| **read (own, RO)** | `Mfn 3` / `0x8000_3000` | reachable RO (read-only leaf) | `S2AP=RO`, XN | guest reads the HV-seeded `0x5EED` | ✅ permits |
| **foreign (granted)** | `Mfn 4` / `0x8000_4000` | reachable RW (RW grant) | `S2AP=RW`, XN | guest writes `0xF00D`; HV confirms via `GuestMemory` | ✅ permits |
| **write → RO** | `Mfn 3` / `0x8000_3000` | **denied** (read-only) | `S2AP=RO` | guest write **faults**: `EC=0x24`, **permission fault** `DFSC=0x0F`, `WnR=1` | ✅ denies |
| **foreign (un-granted)** | `Mfn 5` / `0x8000_5000` | **denied** (no grant) | **no descriptor** | guest read **faults**: `EC=0x24`, **translation fault** `DFSC=0x07` | ✅ denies |
| **unmapped** | `Mfn 6` / `0x8000_6000` | **denied** (not owned/mapped) | **no descriptor** | guest read **faults**: `EC=0x24`, **translation fault** `DFSC=0x07` | ✅ denies |
| **write-xor-pagetable** | `Mfn 1` / `0x8000_1000` | **denied** (typed `PageTable`, not a leaf) | **no descriptor** | guest read **faults**: `EC=0x24`, **translation fault** `DFSC=0x07` | ✅ denies |
| **execute (XN)** | data frames | data, not code | `XN=1` (bit 54) on every data leaf | audited by construction (runtime fetch-fault deferred) | ⏳ by construction |
| **superpage** | — | leaf above `L1` = coarser reach | block path exercised (guest-image 2 MiB block) | model-driven superpage deferred | ⏳ by construction |

The positive rows are **un-forgeable**: `ro=0x5EED` is a value the guest never holds as an immediate
(it appears nowhere in the guest program) — the guest can only echo it by *reading the frame the
hypervisor seeded through the fence*, so it proves the read-only Stage-2 mapping resolves to the
right machine frame. `rw`/`fgrant` are cross-checked by the hypervisor **reading the guest's writes
back** via the realized `GuestMemory`, proving the authorized store landed at the frame the model
authorized (`IPA → PA` correctness).

## The "no more, no less" analysis

- **No isolation hole (no less).** Every frame `G` is *not* authorized to reach has **no leaf edge**
  in `G`'s tables, so the builder emits **no descriptor** for it → translation fault. The un-granted
  peer frame `Mfn 5` and the never-allocated `Mfn 6` both fault (witnessed). Critically — and this is
  the blind refinement auditor's *"canonical catastrophe"* — `G`'s own page-table frame `Mfn 1` is
  **not** a leaf child of any of `G`'s tables, so it is **not** mapped into the data region: the guest
  cannot read (let alone write) its own model page table *as data*, exactly as the model (which types
  it `PageTable`, never a readable leaf) forbids. This is **write-xor-pagetable enforced by real
  hardware** — the headline `p2m` invariant — and it is now witnessed at runtime (`Mfn 1` read →
  translation fault). Foreign presence is gated by the grant: the granted `Mfn 4` is mapped, the
  un-granted `Mfn 5` is not.
- **No liveness hole (no more).** Every leaf edge `G` owns **is** mapped at its exact permission, so
  every authorized access succeeds. A writable leaf is `S2AP=RW`; a read-only leaf is `S2AP=RO` and
  is *readable* (positive) while a *write* to it faults (negative) — the permission dimension is
  enforced in both directions, not merely present.
- **The guest-image region.** The guest's code+stack is identity-mapped as one 2 MiB RWX block
  (infrastructure, not model-driven). This is the guest's **own private RAM** — no other domain's
  memory — so mapping it is no more an isolation hole than a guest reaching its own pages; it carries
  no cross-domain content. Named so it is not mistaken for over-mapping.

## Encoding convergence — the AArch64 Stage-2 values

The descriptor and fault encodings in `stage2.rs` were derived from the Arm ARM and **independently
re-derived by a spec-blind auditor** (no sight of the code), and they agree on every value:

- Descriptor types (4 KiB granule): `L1`/`L2` table `0b11`, `L2` block `0b01`, `L3` page `0b11`
  (the `0b01` "block" pattern is reserved/invalid at `L3`).
- Leaf attributes: `S2AP` bits [7:6] — `0b11`=RW, `0b01`=RO; `MemAttr` bits [5:2] `0b1111` = Normal
  Inner+Outer Write-Back; `SH` bits [9:8] `0b11` = Inner Shareable; `AF` bit 10; `XN` bit 54
  (execute-never at EL1&0, with bit 53 = 0 so it holds under FEAT_XNX too).
- Full words: 2 MiB block RWX = `0x7FD` (bit-identical to Arc 4); 4 KiB page RW = `0x7FF`, RO =
  `0x77F` (plus `XN` on data leaves).
- Fault decode: data abort from lower EL `EC=0x24`; **translation fault** `(DFSC & 0x3C) == 0x04`;
  **permission fault** `(DFSC & 0x3C) == 0x0C`; `WnR` = `ISS` bit 6; faulting IPA from `HPFAR_EL2` =
  `(HPFAR & mask) << 8`.

The two encoding caveats the auditor flagged are **satisfied by our configuration**, so the classic
(non-optional-feature) format is in force: `HCR_EL2.FWB = 0` (we set only `RW`+`VM`, bit 46 clear —
so `MemAttr=0b1111` means Normal-WB) and `VTCR_EL2.DS = 0` (`0x8002_3559`, bit 32 clear — so the
non-LPA2 descriptor format holds). QEMU's observed fault codes — permission `0x0F` (L3) and
translation `0x07` (L3) — match the auditor's from-spec prediction exactly.

## Method — three-way convergence

Per the arc-2–4 discipline (design-lessons #23–#25), the isolation claims were established three
independent ways, and they agree:

1. **Spec-derived code** — `stage2.rs` encodes the AArch64 Stage-2 descriptor/fault fields from the
   Arm ARM; `build_stage2_from_p2m` emits from the model's `link_edges`.
2. **Two spec-blind auditors** — (a) an independent re-derivation of the descriptor/fault
   **encodings** from the Arm ARM (converged, above); (b) an independent re-derivation of the
   **model→reachability refinement** — what the Stage-2 *should* permit/deny for this configuration,
   from `p2m.rs` alone, blind to `stage2.rs`/`guest.rs`. It reproduced the whole matrix and its two
   *sharp discriminators* — `Mfn 5` read → **translation** fault (not success, not permission) and
   `Mfn 3` write → **permission** fault (not translation) — which are exactly the fault classes QEMU
   produced (`0x07` vs `0x0F`). It also independently named `Mfn 1` (G's page-table frame) as the
   case that must **not** be mapped (added as the write-xor-pagetable probe), and flagged three
   generalization caveats carried below as F4.
3. **The running emulator** — QEMU booted the image and produced the full authorize/deny matrix: the
   authorized accesses succeeded (with un-forgeable readbacks), and the three denials faulted with
   the exact expected class and faulting IPA. QEMU is architecturally faithful about Stage-2
   translation + fault semantics for CPU-initiated accesses, so it is a sound third oracle
   (`docs/QEMU-AND-METAL.md`).

## Findings

- **F1 — superpage runtime witness deferred (scope, below-bar).** The builder exercises the 2 MiB
  block path (guest image) but the *negative test* runs on 4 KiB leaves. A model-driven superpage
  leaf mapped by an `L2` block, with its own authorize/deny probe, is deferred. No isolation content
  is lost: a superpage is the same reachability relation at coarser granularity, and the block
  encoding (`0x7FD`) is already the proven-good Arc-4 value. Named, not swept.
- **F2 — execute-never (XN) audited by construction, runtime fetch-fault deferred (scope,
  below-bar).** Every data leaf carries `XN=1`, so an instruction fetch from a data frame would fault
  on both QEMU and metal; a runtime witness (a guest that jumps into a data page and is faulted)
  is deferred. The descriptor bit is correct by construction and converged with the blind auditor.
- **F3 — the crate-wide EL2-MMU real-HW gap is untouched (carried forward, out of scope).** Arc 5 is
  QEMU-only and QEMU is a sound oracle for Stage-2 faults, so the guest Stage-2 work is fully
  diamondable here. The EL2 stage-1 MMU (its own `SCTLR_EL2.M=0`) is orthogonal to guest Stage-2 and
  stays named-and-deferred to the dedicated pre-real-HW arc (`docs/ARC-4-TRAP-AND-SERVICE.md`,
  "Real-hardware readiness"). Not an Arc-5 finding; recorded so the boundary stays honest.

- **F4 — refinement-relation generalizations named by the blind auditor (scope, not defects here).**
  The relation is sound *for this configuration*; the auditor flagged four ways it must generalize as
  the model grows, none exercised by the single-`L1` test and so none a defect now, all carried
  forward: (i) *"a table G owns"* should tighten to *"a table reachable from G's active root"* — a
  multi-level tree could have a detached owned table whose leaves must **not** enter the guest's
  address space; (ii) a **read-only leaf onto a page table** (the model's legal linear-map view) must
  emit `S2AP=RO`, never upgrade to writable — not present here; (iii) a **read-only-granted** foreign
  frame must be capped at `S2AP=RO` in Stage-2 — this config grants `Mfn 4` read-write, so the RO-grant
  edge is a *test-coverage* gap; (iv) **foreign interior-node sharing** exposes data through leaves
  under a parent table the *peer* owns, so a literal reading of *"leaf child of a table G owns"* would
  miss them (a liveness gap) or, if mapped, must AND-down the node's read/write bound — this is the
  Stage-1 node-sharing dimension already named out-of-scope for Arc 5's leaf-level Stage-2 refinement.

None of these is a soundness defect in the refinement as realized. That the findings are deferred
*granularity/witness/generalization* dimensions plus one pre-existing carried-forward gap is itself
the result: the model→page-table refinement denies exactly what the model forbids, and permits exactly
what it authorizes, across read / write / foreign(granted) / unmapped / write-xor-pagetable, witnessed
on every boot.

## Diamond review pass (post-merge)

After the arc landed, a dedicated review pass re-examined the implementation from three *adversarial*
angles — **four independent perspectives + empirical mutation testing** — in the arc-4 rhythm
(design-lesson #26). **Verdict: SOUND, no defect.**

- **Three spec-blind auditors, orthogonal axes, all CLEAN.** (i) *Rust/unsafe soundness* — no UB, no
  aliasing violation; every table index provably `< 512`, `frame_pa` provably inside the exactly-2 MiB
  window, `GuestMem::ipa_to_pa` bounds-checked, and **no new exclusive/atomic on Device memory** (the
  Arc-5 fault-record statics are `.store`/`.load` only; only the pre-existing `IN_GUEST_HANDLER.swap`
  remains, within the named EL2-MMU gap). (ii) *False-green / witness integrity* — could not construct
  a false-green: every asserted marker is conditionally gated, `is_translation(0)`/`is_permission(0)`
  are both `false` so a probe that never faulted is scored *not-denied* (a skip can't masquerade as a
  denial), and the positives are un-forgeable (`0x5EED` appears in no guest immediate; `rw`/`fgrant`
  are cross-read by the hypervisor via `GuestMemory`). (iii) *Cross-arc composition* — Stage-2
  registers mutually consistent, no Arc-2 vector regression, no linker collision; it surfaced that
  `__guest_data_start == __guest_ram_end`, so the data-frame **host PAs sit outside the guest's only
  identity mapping** — the guest can reach them solely through the IPA-gated `L3` path, so **isolation
  holds by construction**, not merely by test.
- **Empirical mutation testing** (the "remove the fix → tool rejects" discipline, #24). Three
  single-line perturbations that *should* break isolation were applied and booted; the self-test
  **caught all three**: (1) mapping the un-granted peer frame (isolation hole) → its read no longer
  faults → `negative_ok=false` → FAIL; (2) emitting `S2AP=RW` for the read-only leaf (permission
  bypass) → the RO-write no longer faults → FAIL (while `positive_ok` stays true, so the failure is
  *exactly* the RO-write dimension); (3) skipping an authorized frame (over-restriction / liveness
  hole) → the positive readback mismatches *and* `rw_faulted` → FAIL. The test discriminates
  isolation holes, permission bypasses, **and** over-restriction.
- **Three below-bar findings, all fixed in the review-pass hardening** (none a soundness defect): a
  `DFSC`-sentinel comment was imprecise (`DFSC=0x00` is a valid address-size fault, unreachable by the
  probed IPAs — reworded to state *why* the `0` sentinel is sound: it is never *scored as a denial*);
  a stale `GUEST_VMID` doc line referenced a guest-side constant that no longer exists (reworded); and
  `NFRAMES` (the fault-array size and region bound) was independently defined from `NUM_FRAMES` —
  hardened with a `const _: () = assert!(NFRAMES >= crate::NUM_FRAMES)` so a future model growth can't
  silently push a probeable frame past the array.

## Verdict

**The emitted Stage-2 table realizes the proven `p2m` for CPU data access — it denies exactly what
the model forbids and permits exactly what it authorizes, across read / write / foreign(granted) /
unmapped, three-way-converged and witnessed on every boot; a four-perspective diamond review pass plus
mutation testing found no soundness defect.** `GuestMemory` is now **realized** on ARM
(the assumption Audit #1 named for this arc, closed), behind the neutral fence — no descriptor bit
leaks into a signature. Superpage and execute-never runtime witnesses are named-deferred; the
crate-wide EL2-MMU gap is untouched and carried forward. No soundness defect. Arc 5 *refines* the
proof — the first **isolation** content on the metal — and is QEMU-sound for CPU-initiated Stage-2
faults, the honest scope per the ledger.

## The M4 HAL ledger — `hv-hal` traits, Arc 5 status

Continuing the M4 ledger (`docs/ARC-4-TRAP-AND-SERVICE.md`). No trait *signature* changed — the fence
stays architecture-neutral (Audit #1) — this records what Arc 5 realizes on ARM.

| trait / method | neutral? | ARM metal (Arc 5) | fidelity check | verified scope |
|---|---|---|---|---|
| `TimeSource::now` | ✅ | ✅ realized (Arc 3, `CNTPCT_EL0`) | `witness_advance` every boot | *refines* — honored |
| `VcpuOps::set_entry` | ✅ | ✅ realized (Arc 4, `ELR_EL2`) | guest runs from the set entry every boot | *refines* — honored |
| `VcpuOps::inject_interrupt` | ✅ | ⏳ deferred — no GIC yet | when interrupt delivery lands | *assumption named* |
| `GuestMemory::read`/`write` | ✅ | ✅ **realized this arc** — IPA→PA via the shared `stage2` layout; seeds the RO frame + reads guest writes back | the un-forgeable `ro=0x5EED` readback + the RW/foreign write-backs, every boot | *refines* — honored |
| global allocator | n/a | ✅ bump over `.bss` (Arc 3, `heap.rs`) | constructs the guest `Hypervisor` + the model config every boot | *plumbing* — no reclaim |

### Honest deferred-items note

- **`GuestMemory`** is realized for the guest's model-data region (the isolation surface); it
  translates IPA→PA through the same layout the Stage-2 builder emits. It is *unconditional on the
  guest's `S2AP`* by design — this is the trusted hypervisor accessing guest memory (e.g. seeding a
  read-only frame the guest may then only read), not a guest access. The guest-image region is the
  guest's private code+stack, which the hypervisor has no reason to touch, so it is not exposed
  through this map.
- **`VcpuOps::inject_interrupt`** stays deferred: there is no GIC and no interrupt source yet.
- **Runtime invariant checks** remain compiled out on the release metal build (`debug_assert!`), as
  Audit #1 named: the metal trusts the ∀-N proof, it does not re-check it at runtime.
- **Superpage / execute-never runtime witnesses** deferred (F1, F2); the **EL2-MMU real-HW gap**
  untouched and carried forward (F3).
