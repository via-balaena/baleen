<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# M5 Arc 3 — virtio-mmio console, live (the ring IS a proven grant)

The first **device** arc. A synthetic guest drives a **real** virtio-mmio v2 console device — emulated
in EL2 as the backend of the control domain (`dom0`) — and its bytes reach the PL011 console through a
**real split virtqueue**. The isolation content is small and sharp: the shared memory a virtio device
uses (the descriptor table, the available/used rings, the data buffers) is **not** an unaudited hole.
Every byte the backend reads from or writes to guest memory is **authorized by the proven `hv-core`
grant** — the guest owns the ring frames and *grants* them to `dom0`, and an access to a frame the
guest did **not** grant is refused. The virtqueue *is* a grant. This refines (no new hv-core invariant);
`hv-core`/`hv-hal` are untouched.

## Scope — real vs. synthesized (named for the audit)

- **Real (so a Linux virtio-console driver works unchanged at the capstone):** the virtio-mmio v2
  register file + its `Status` handshake, the `VIRTIO_F_VERSION_1` feature negotiation, and the **split
  virtqueue** layout (descriptor table / available ring / used ring) packed exactly as virtio 1.x lays
  them out in guest memory.
- **Synthesized (this arc):** the *driver* — a hand-written guest that drives the mmio registers and
  builds descriptors, standing in for Linux's virtio-mmio + virtio-console drivers (the real Linux guest
  is the Arc-5 capstone). **TX only** (guest → host console output); RX deferred. One console device, one
  queue, one non-chained/non-indirect descriptor per buffer.
- Cooperative, single physical CPU (as prior arcs). The backend runs **in EL2 as dom0** synchronously on
  the notify trap.

## The trap-and-emulate transport (new metal capability)

The device's mmio window (`0x0a00_0000`, the QEMU `virt` convention) is left **unmapped** in the guest's
Stage-2, so a guest load/store to a device register faults to EL2 (`EC=0x24`). `handle_data_abort` routes
a `FAR_EL2` in that window to `handle_mmio`, which decodes the abort syndrome — `ESR_EL2.ISS` gives the
access size (`SAS`), the target GP register (`SRT`), and direction (`WnR`); `FAR_EL2` gives the full
faulting address (Stage-1 is off, so guest VA == IPA, and the low bits are the register offset). It
services the register in the device model, writes any read result back into the guest's saved register
frame, and advances `ELR`. Genuine trap-and-emulate of a device register file, distinct from the pure
isolation-fault probes of Arcs 5/0/2.

## The grant bridge — the heart

The guest lays a split virtqueue out in a frame it owns (`F_VQ`: descriptors @ +0, avail @ +0x100, used
@ +0x200) and a TX buffer in another (`F_BUF`), and **grants both to dom0** (the ring read-write — the
backend writes the used ring; the buffer read-only — the backend only reads TX data). On `QueueNotify`,
the backend walks avail → descriptor → buffer and drains to the console. **Every** guest-memory access
goes through `backend_authorize`:

> recover the frame `mfn` the access lands in (`(gpa − DATA_IPA_BASE)/FRAME_SIZE`), reject a
> frame-straddling access, then require `hv.grant().authorizes(guest, dom0, mfn, writable)` — the proven
> grant seam. A frame the guest did not grant is **refused**.

The descriptor addresses are **untrusted guest data**; each one the backend dereferences is checked. That
is what makes the ring a grant.

## The matrix (the deliverable)

Driven end-to-end in one boot (phase 5, chained off the concurrent-isolation terminal):

1. **Identify** — the driver reads Magic/Version/DeviceID/VendorID through the trap-and-emulated register
   file (`"virt"` / 2 / 3 console).
2. **Negotiate** — the driver walks the `Status` handshake (ACKNOWLEDGE → DRIVER → FEATURES_OK), accepts
   `VIRTIO_F_VERSION_1`, and reads `Status` back to confirm the device left FEATURES_OK set.
3. **Positive** — the driver grants `F_VQ`+`F_BUF`, sets up the queue, writes its message, kicks; the
   backend grant-checks every access and drains **"baleen-guest: hello over a granted virtqueue"** to the
   console.
4. **Negative (the diamond)** — the driver builds a second descriptor pointing at `F_BUF_UNGRANTED` (a
   frame it owns but did **not** grant) holding a SECRET; the backend's grant check **refuses** it, so the
   SECRET never reaches the console. `boot-test` makes the SECRET's absence a **forbidden marker** (a
   grant-bypass would leak it).

`VIRTIO CONSOLE TEST PASSED` prints only when identify + negotiate + granted-delivery + un-granted-refusal
all hold.

## Method — three-way convergence + mutation testing

Spec-derived code + independent re-derivation (the virtio 1.x mmio/virtqueue spec; the AArch64 abort
syndrome) + a live QEMU boot, all agreeing. The diamond review pass adds empirical **mutation testing** of
the grant seam — bypass the check (→ SECRET leaks, forbidden-marker caught), over-restrict (→ granted
delivery fails), key the check on the wrong frame (→ leaks) — all three caught; plus three spec-blind
auditors (see `docs/AUDIT-5-VIRTQUEUE-GRANT.md`).

## Files

- `hv-metal/src/virtio.rs` (new) — the virtio-mmio v2 console register file + `Status` handshake +
  split-virtqueue field offsets.
- `hv-metal/src/guest.rs` — the MMIO trap decode (`handle_mmio` + `read_esr_far`), the grant-checked
  backend (`backend_authorize`/`backend_read`/`backend_write` + `handle_virtio_notify` +
  `backend_drain_to_console`), the driver guest program, and phase-5 setup (`begin_virtio_console_phase5`).
- `hv-metal/boot-test.sh` — the phase-5 markers + the `FORBIDDEN_MARKERS` guard (the SECRET must never
  appear).
- `docs/AUDIT-5-VIRTQUEUE-GRANT.md` — Architecture Audit #5.

## Verdict

The guest's bytes flow to the console through a real virtqueue whose every frame is grant-authorized, and
an access to an un-granted frame is refused on hardware-checked model authority. The ring is a proven
grant. See Audit #5 for the per-dimension verdict and the diamond review pass.
