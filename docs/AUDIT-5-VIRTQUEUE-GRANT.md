<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Architecture Audit #5 — the virtqueue is a proven grant

Audit #2 asked whether the emitted Stage-2 denies *exactly* what the model forbids. Audit #5 asks the
device-plumbing question M5 Arc 3 raises: when a virtio backend reads and writes the guest's virtqueue,
is that shared memory a **consented grant** — authorized by the proven `hv-core` grant model — or an
unaudited hole? The audited surface is the backend's guest-memory access path in
`hv-metal/src/guest.rs` (`backend_authorize` and its callers) plus the virtio device model in
`hv-metal/src/virtio.rs`. `hv-core`/`hv-hal` are untouched (this refines).

## The charter — no access without a grant

> Every byte the virtio backend (acting as `dom0`) reads from or writes to guest memory — the available
> ring, the descriptor table, the data buffers a descriptor points at, and the used ring — must be
> authorized by a **grant from the guest to `dom0`** for the frame the access lands in, at the needed
> permission. An access to a frame the guest did not grant is refused, and no data crosses.

The descriptor addresses are untrusted guest data; the audit's crux is that *every* address the backend
dereferences is checked against the grant table, not assumed.

## The refinement — `backend_authorize` = the grant seam

For an access of `len` bytes at guest IPA `gpa` with writability `writable`:

1. **Frame recovery** — `mfn = (gpa − DATA_IPA_BASE) / FRAME_SIZE` (`gpa_to_mfn`), the inverse of the
   shared `frame_ipa`/`frame_pa` layout `GuestMem` also uses, so the frame *checked* is the frame
   *accessed*.
2. **Single-frame bound** — `(gpa & (FRAME_SIZE−1)) + len ≤ FRAME_SIZE`; a grant authorizes one frame,
   so a straddling access is refused.
3. **The grant** — `hv.grant().authorizes(VIRTIO_DOM, VIRTIO_BACKEND, mfn, writable)`
   ([`hv_core::grant::System::authorizes`]), which requires an active `Access` grant `guest → dom0` for
   that frame with `(!writable || !readonly)` — a writable access needs a read-write grant.

`backend_read`/`backend_write`/`backend_read_u16|u32|u64` all funnel through it before touching
`GuestMem`. A refusal records the negative witness and returns without moving bytes.

## The test configuration (driven through the real model)

`begin_virtio_console_phase5`, through the real `Hypervisor::dispatch`:

- The guest domain (`VIRTIO_DOM`) allocates a page-table root + three data frames: `F_VQ` (the split
  virtqueue), `F_BUF` (the TX buffer), `F_BUF_UNGRANTED` (the negative). It links all three writable.
- It **grants** `F_VQ` read-write (gref 0) and `F_BUF` read-only (gref 1) to `dom0`. `F_BUF_UNGRANTED` is
  deliberately **not** granted.

So the model holds two `Access` grants guest→dom0; the third frame is owned-but-un-granted.

## Per-dimension verdict — model vs. backend vs. QEMU

| Dimension | Grant model | Backend access | QEMU witness | Verdict |
|---|---|---|---|---|
| **available ring read** | `F_VQ` granted RW | `authorizes(…, F_VQ, false)` ✓ | avail.idx/ring read, drives the walk | ✅ |
| **descriptor read** | `F_VQ` granted RW | `authorizes(…, F_VQ, false)` ✓ | addr/len parsed | ✅ |
| **granted buffer read** | `F_BUF` granted RO | `authorizes(…, F_BUF, false)` ✓ (RO grant, read) | "baleen-guest: hello…" on the console | ✅ |
| **used ring write** | `F_VQ` granted RW | `authorizes(…, F_VQ, true)` ✓ (needs RW) | used.idx/elem written | ✅ |
| **un-granted buffer read** | `F_BUF_UNGRANTED` NOT granted | `authorizes(…, Mfn 4, false)` → **false** | REFUSED; SECRET never printed | ✅ |
| **frame recovery** | frame keyed by `Mfn` | `gpa_to_mfn` inverts `frame_ipa`; check-frame == access-frame | granted delivery lands, un-granted refused | ✅ |

The RO-vs-RW permission distinction is live: the buffer's read-only grant authorizes the backend's read
but would refuse a write; the ring's read-write grant is needed for the used-ring write. The negative is
pinned to the RIGHT cause — the grant table returns false for a frame with no `Access` entry, not an
incidental refusal.

## The "no more, no less" analysis

- **No more.** The only guest memory the backend can reach is a frame the guest granted `dom0`. The
  descriptor's `addr` is untrusted, so it is grant-checked (`F_BUF_UNGRANTED` proves the refusal); a
  frame-straddling access is rejected; a gpa below the data region has no frame and is refused.
- **No less.** Every frame the guest *did* grant at the needed permission is accessible, so the honest
  TX path completes (the message is delivered, the used ring retired).
- **The trap boundary.** The device registers themselves are emulated in EL2 (trap-and-emulate); they
  are device state, not guest memory, so they need no grant. Only the DMA-like virtqueue/buffer accesses
  — the ones that read/write *guest* frames — go through the grant. That is the correct seam.

## Mutation testing — the grant seam is load-bearing

Each mutation perturbs the grant gate in a way that *should* break the property; the boot-test must catch
it (the `PASSED` marker absent, or the forbidden SECRET present). All on QEMU `-cpu max`.

| # | Mutation | Expected | Observed | Caught? |
|---|---|---|---|---|
| 1 | **bypass** — `backend_authorize` returns `true` always | the un-granted buffer is read → SECRET leaks | `secret_leaked=1, refused_ok=false`, forbidden-marker fires | ✅ |
| 2 | **over-restrict** — `backend_authorize` returns `false` always | the granted buffer is refused → nothing delivered | `delivered=0, passed=0` | ✅ |
| 3 | **wrong frame** — the check keys on a fixed granted frame, not the accessed `mfn` | an un-granted access authorizes → SECRET leaks | `secret_leaked=1` (forbidden-marker fires) | ✅ |

Mutation 1 confirms the check *exists*; mutation 3 confirms it reads the *real* accessed frame from the
grant table (not a hardcoded frame number); mutation 2 confirms the positive genuinely *depends* on the
grant. The `FORBIDDEN_MARKERS` guard (the SECRET must never appear) is load-bearing for the leak
mutations — a bypass that reaches the console is caught even though `PASSED` might still print.

## Method — three-way convergence

Spec-derived code + independent re-derivation (the virtio 1.x mmio/virtqueue spec; the AArch64 abort
syndrome; the hv-core grant semantics) + a live QEMU boot, all agreeing, plus the three-mutation
empirical pass. The diamond review pass adds three spec-blind auditors on orthogonal axes (unsafe/asm +
MMIO decode; false-green / witness integrity; grant-refinement vs the actual hv-core source).

## Diamond review pass — auditor findings

Three spec-blind auditors on orthogonal axes, each re-deriving independently (the Arm ARM abort
syndrome; the witness logic; the actual hv-core grant model). **All three: no soundness bug.** Five
below-bar findings, all folded in (all robustness/witness-tightening — no change to the isolation
property):

1. **Unsafe / asm + MMIO decode (auditor A) — SOUND.** Re-derived the ESR/ISS decode (ISV/SAS/SRT/WnR),
   the write-back width (32-bit `ldr w` zero-extend), `FAR==IPA` (Stage-1 off), the `+4` resume, and the
   whole `guest5` virtqueue arithmetic — all correct. Untrusted guest data (wild `head`/`avail_idx`)
   cannot breach: any non-granted frame is refused at the gate, the drain caps `len` into a fixed
   buffer, the loop terminates. **Folded:** (a) scoped the `VIRTIO_DEV` borrow in `handle_mmio` so it is
   dropped before `handle_virtio_notify` re-borrows it (no two live `&mut`, benign but now unambiguous);
   (b) a fail-loud `SAS==word` guard (a future non-word/config-space access halts rather than
   mis-emulates); (c) a fail-loud `FnV` guard (a `FAR`-invalid abort halts rather than routes on a
   garbage address).
2. **False-green / witness integrity (auditor B) — no bug.** Confirmed the composite gate is sound: the
   delivery + refusal + SECRET-absence markers are guest-owned `.asciz` bytes / frame-specific / a
   forbidden-marker, all un-forgeable by the metal; the refusal is the grant check specifically; the
   SECRET is blocked by nothing but the grant. **Folded:** (A) `VIRTIO_DRAINED_OK` now gates on bytes
   actually delivered (`written > 0`, never cleared by a later refused kick) rather than being set
   unconditionally; (B) `VIRTIO_UNGRANTED_REFUSED` is set only on the grant-table refusal branch, not
   the malformed-access ones, so the negative witness names its own cause. Both now witness their own
   property instead of leaning on the boot-test markers — verified: the over-restrict mutation now fails
   `drained_ok` at the in-code level.
3. **Grant-refinement vs actual hv-core (auditor C) — FAITHFUL.** Traced all 8 guest-memory touches in
   the backend; every one funnels through `backend_authorize` (no raw `GuestMem` access in the path).
   `gpa_to_mfn` is the exact inverse of `frame_ipa`, consistent with `GuestMem.ipa_to_pa` (check-frame ==
   access-frame); the frame-boundary check confines each access to the one authorized frame; the u32
   `Mfn` truncation edge is caught by `GuestMem`'s window bound; the RO/RW permission logic is correct
   (used-ring write needs the RW grant, buffer read accepts the RO grant); the un-granted refusal is a
   genuine model decision keyed on the grant table, not a hardcoded allow-list. **Non-issue scope note:**
   `authorizes` checks the grant, not p2m ownership of the frame (a documented boundary of the grant
   model — ownership is enforced at the `grant_map`/p2m seam); in this harness the guest only grants
   frames it allocated, so the claim is faithfully met.

Own re-read + the three-mutation empirical pass corroborate. Every fold is a robustness or
witness-tightening change; the grant-gating logic and the isolation property are unchanged. Post-fix:
metal-lint clean, the full boot sequence (both configs) green.

## Verdict

**SOUND — no defect.** A real virtio-mmio v2 console with a real split virtqueue runs on the metal, and
the backend's every access to guest memory — the available ring, the descriptor table, the untrusted
buffer addresses, the used ring — is gated on the proven `hv-core` grant (`authorizes(guest, dom0, mfn,
writable)`). The guest's bytes reach the console through frames it granted; a descriptor pointing at a
frame it did not grant is refused, and its payload never crosses. Three spec-blind auditors on
orthogonal axes converged SOUND; three grant-seam mutations (bypass, over-restrict, wrong-frame) are all
empirically caught, with the SECRET-absence forbidden-marker load-bearing. Below-bar findings folded
(borrow scoping, two fail-loud MMIO guards, two witness-tightenings). The ring is a proven grant.
