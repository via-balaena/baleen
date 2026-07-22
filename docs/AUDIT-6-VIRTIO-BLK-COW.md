<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Architecture Audit #6 — the CoW disk keeps writes off the template

Audit #5 established that a virtio backend's every touch of guest memory is a proven grant. Audit #6 asks
the storage question M5 Arc 4 raises: when a virtio-blk backend serves reads and writes against a shared
**read-only template** and per-tenant **copy-on-write overlays**, does the CoW discipline actually keep a
guest's write off the template and off a peer's view? Two orthogonal surfaces are audited per dimension:
the **grant** surface (guest-memory access, an Arc-5 regression) and the new **CoW** surface (the disk).
The audited code is `hv-metal/src/blk.rs` (the `BlkDisk` store + device model) and
`hv-metal/src/guest.rs` (the block backend + witnesses). `hv-core`/`hv-hal` are untouched (this refines).

## The charter

> (A) **template-immutability** — no block request path may mutate the shared template after it is
> seeded; a guest's write lands only in that guest's overlay.
> (B) **overlay-isolation** — a tenant's read returns its own overlay (for sectors it has written) or the
> shared template (for sectors it has not); it never returns another tenant's overlay, and two tenants'
> overlays are distinct storage.
> (C) **the grant surface holds across a descriptor chain** — every backend touch of guest memory across
> the { header, data, status } chain is grant-authorized; an un-granted data buffer is refused.

## The refinement — where each property lives

**CoW store (`BlkDisk`, `hv-metal/src/blk.rs`).** Storage is `template: [[u8;512]; DISK_SECTORS]` plus
`overlay: [[[u8;512]; DISK_SECTORS]; N_TENANTS]` and `dirty: [[bool; DISK_SECTORS]; N_TENANTS]`.

- `read(t, s) = dirty[t][s] ? overlay[t][s] : template[s]` — a clean sector falls through to the shared
  template; a written sector diverges into the tenant's private overlay.
- `write(t, s, d) = { overlay[t][s] = d; dirty[t][s] = true }` — a write mutates **only** `overlay`.
- `seed_template(s, d)` — the sole writer of `template`, called once before any tenant runs.

Property (A) holds by construction: no method other than `seed_template` writes `template`, and
`seed_template` is called exactly once (in `begin_virtio_blk_phase6`, before either guest runs; the disk
is a persistent static, so it is **not** re-seeded between tenant 0's write and tenant 1's read).
Property (B) holds by construction: `overlay` and `dirty` are indexed by tenant first, so one tenant's
writes are invisible to another's reads, and `overlay[0]` / `overlay[1]` are distinct storage.

**Grant surface (`process_blk_request`, `hv-metal/src/guest.rs`).** The backend walks the chain
`head → next → next` (each descriptor read via the grant-checked `backend_read_desc`), then:

- a read (`T_IN`) authorizes a **writable** access to the guest's data buffer (`backend_authorize(.., true)`)
  before DMAing the CoW-read sector into it;
- a write (`T_OUT`) authorizes a **readable** access before reading the buffer and CoW-writing the overlay;
- the status byte is written through the grant-checked `backend_write`.

Every access reuses Arc-5's `backend_authorize` (frame recovery via `gpa_to_mfn`, single-frame bound,
`hv.grant().authorizes(guest, dom0, mfn, writable)`), so the grant refinement is Audit #5's, unchanged;
Arc 4 adds only the chain walk and the device-writable direction (an RW grant for a read's buffer).

## The seam — the disk is not guest memory

The template and overlays live in a backend-owned static (`BLK_DISK`), at host PAs that **no guest's
Stage-2 ever maps** — `build_stage2_from_p2m` maps only the guest's own model frames into the guest's
IPA window, and the disk static is not among them. So a guest cannot reach the disk directly; it reaches
it only through the grant-mediated DMA descriptors the backend services. This is the same
distinct-PA-⇒-disjoint-by-construction argument Audit #4 used for two domains' Stage-2, applied at the
device layer. Correctly, the disk is **not** grant-gated (it is not guest memory); only the guest-buffer
DMA is (it is).

## Verdict per dimension

| dimension | forbidden | mechanism | witness | verdict |
| --- | --- | --- | --- | --- |
| (A) template-immutability | a write mutates the template | `write` touches only `overlay`; `seed_template` is the sole template writer, called once | HV-side: after tenant 0's write, `template_sector(0) == seed` AND `overlay_sector(0,0) == poison` (`BLK_WRITE_ISOLATED_OK`) | ✅ |
| (B) overlay-isolation | tenant 1 sees tenant 0's write | per-tenant `overlay`/`dirty` rows; clean sector falls through to template | tenant 1's round-trip read `== template` (`BLK_READ_TEMPLATE_OK[1]`); `overlay_ptr(0,0) != overlay_ptr(1,0)`; `POISON` forbidden-marker absent | ✅ |
| (C) grant across the chain | an un-granted buffer is served | every chain access via `backend_authorize` → `hv.grant().authorizes` | un-granted data buffer (Mfn 5) refused (`BLK_UNGRANTED_REFUSED`); no bytes cross | ✅ |

**Verdict: SOUND, no defect.** Both isolation properties fall out of the by-construction structure of the
CoW store (per-tenant rows, template-write-once) and the reused proven grant; the witnesses are HV-side
and un-forgeable (the immutability check reads the backend's real storage, not a re-seeded copy), and the
poison is a forbidden-marker so a leak cannot be silently green.

## Review pass — three spec-blind auditors + empirical mutation testing

Three auditors reviewed the committed implementation on orthogonal axes, each spec-blind (told the axis,
not the expected conclusion). **All three: SOUND, no defect.**

- **unsafe / asm / MMIO.** Verified every `virtq_desc` field write against the 16-byte layout and the
  avail/used ring offsets in both guest programs (store widths, IPA `movz/movk`, position-independence);
  the `UnsafeCell` statics' single-CPU / non-nested-handler discipline (no two live `&mut` to one cell);
  `srt < 31` frame bounds; the ISV-gated MMIO decode; and untrusted-descriptor bounds (sector clamp, `n`
  clamp, no `next`-following loop, `backend_authorize` short-circuits before the CoW read). Empirically
  confirmed by a clean boot.
- **false-green / witness integrity.** Traced every `*_OK` witness and ran three break-and-run mutations
  (below). No witness is set spuriously; the negative names its own cause (`BLK_UNGRANTED_REFUSED` set
  only on the grant-fail branch, and the on-console marker binds to `Mfn 5`); the HV-side immutability
  check reads the live `BLK_DISK` the backend mutates (not a re-seeded copy); the template is seeded
  exactly once (not re-seeded for tenant 1), so tenant 1's pristine read is a real cross-phase property.
- **model refinement vs ACTUAL hv-core.** Read `hv-core/src/grant.rs` `authorizes(grantor, grantee,
  frame, writable)` directly: the metal calls it with the correct order/meaning, the RW/RO grant
  permission matches the device-writable/readable descriptor direction, the checked frame equals the
  accessed frame (`gpa_to_mfn` = inverse of the `GuestMem` layout), the single-frame bound is present,
  and every guest-memory touch across the chain is gated. The disk is a backend static outside the
  `GuestMem` window, so no crafted descriptor address can reach it. `hv-core`/`hv-hal` untouched.

### Empirical mutation testing (each perturbation reverted; each self-test FAILED as required)

| mutation | breaks | caught by |
| --- | --- | --- |
| **write-reaches-template** — `BlkDisk::write` mutates `template[sector]` | template-immutability | immutability marker absent, `write_isolated_ok=false`, tenant-1 read mismatch, **POISON printed** (forbidden fired) |
| **bypass-CoW / grant-bypass** — skip `backend_authorize` on the data buffer | the grant surface | `Mfn 5` refusal marker absent, `refused_ok=false`, **POISON leaked** |
| **two-overlays-alias** — key `read` on a fixed tenant 0 | overlay-isolation | `t1_read_ok=false`, PASSED marker absent, **POISON leaked** |

Every mutation is caught through multiple independent channels, and the `POISON` forbidden-marker is
load-bearing for all three leak classes — a broken property cannot go silently green.

### Below-bar fixes folded into the review-pass commit

- **DomId coupling pinned** — `backend_authorize` names the grantor/grantee by the console's
  `VIRTIO_DOM`/`VIRTIO_BACKEND`; a `const _: () = assert!(BLK_DOM == VIRTIO_DOM && BLK_BACKEND ==
  VIRTIO_BACKEND)` now fails the build if a future arc gives the block device distinct DomIds (which
  would otherwise silently mis-gate).
- **Fail-loud MMIO width guards** — `handle_mmio` now halts on `FnV` (FAR invalid → can't trust the
  register offset) and on a non-word `SAS` (the virtio-mmio register file is 32-bit; a byte/half/dword
  access would be mis-emulated). Harmless to the synthetic drivers (all word-width); hardens the shared
  handler for the Arc-5 real-Linux capstone.
- **Witness hygiene** — `overlays_distinct` is reframed in-code as a by-construction *structural*
  assertion; the live overlay-isolation discriminators are `t1_read_ok` + the absent POISON marker.

**Review-pass verdict: SOUND, no soundness defect. Arc 4 is diamond-grade.**
