<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# M5 Arc 4 — virtio-blk + copy-on-write template storage

The second **device** arc, and the storage half of the isolation thesis. Two synthetic guests drive a
**real** virtio-blk device (`DeviceID` 2) — emulated in EL2 as the backend of the control domain
(`dom0`) — over a split-virtqueue **descriptor chain**, backed by a shared **read-only template** and a
per-guest **copy-on-write overlay**. It extends Arc 3's grant-gated virtqueue backend in exactly the two
ways a block device needs, and adds the CoW disk store. This refines (no new `hv-core` invariant);
`hv-core`/`hv-hal` are untouched.

## The diamond (Audit #6) — two orthogonal isolation surfaces

1. **Guest-memory isolation (grant-anchored, a regression of Arc 3).** Every backend touch of guest
   memory across the chain — the available ring, each descriptor, the request header, the data buffer,
   the status byte, the used ring — is authorized by the proven `hv-core` grant
   (`grant::authorizes(guest, dom0, mfn, writable)`). A descriptor whose data buffer points at an
   **un-granted** frame is refused (`baleen: virtio backend REFUSED un-granted access to Mfn 5`), the
   request errors, and no bytes cross. The new content here vs. Arc 3 is the **descriptor chain** walk
   and the **device-writable** data buffer of a read (a grant-checked *write* into guest memory; Arc 3
   was device-read TX only), so the RO/RW permission of the grant is live: the header is served by an RO
   grant, the data/status by an RW grant.
2. **Disk isolation (the new Arc-4 content).**
   - **template-immutability** — a guest's **write** lands in *its* overlay, never the template. Witnessed
     HV-side, un-forgeably: after tenant 0 writes the poison payload to sector 0, the backend reads the
     disk's backing directly and confirms the overlay holds the poison while the template is byte-for-byte
     the seed (`virtio-blk template-immutability OK`).
   - **overlay-isolation** — a **second tenant** reading the sector the first poisoned sees the **pristine
     template**, not the poison, over a **distinct** overlay (`virtio-blk read round-trip OK: tenant 1
     read sector 0 = the pristine template`, and the two overlays are distinct storage — never aliased).
     The poison is a `FORBIDDEN_MARKERS` payload: it reaches the console only if a write leaks to the
     template or two tenants' overlays alias.

## The seam split (design-lesson #31d, carried to storage)

The **disk** (template + overlays) is **backend/device-model storage** — it lives in a static owned by
the EL2 backend and is **never mapped into any guest's Stage-2**, so no guest can reach it directly
(unreachable by construction, Arc 2's distinct-PA argument at the device layer). A guest reaches the disk
**only** through the grant-mediated DMA descriptors — exactly as real virtio-blk. So the CoW logic is
device-model content proven by construction + witness + mutation, while every access to *guest* memory
stays anchored to the proven grant. Two surfaces, each proven the right way; don't over-gate (the disk is
not guest memory) and don't under-gate (every guest-buffer touch is a grant).

This is precisely the **disposable-from-template** primitive the Arc-6 thesis cashes in: a disposable is a
CoW overlay on a shared RO template, and destroying it discards the overlay while the template stays
pristine for the next tenant.

## The copy-on-write disk (`hv-metal/src/blk.rs`)

```
BlkDisk {
    template: [[u8; 512]; DISK_SECTORS],            // the shared golden image — seeded once, RO after
    overlay:  [[[u8; 512]; DISK_SECTORS]; N_TENANTS] // per-tenant private copies
    dirty:    [[bool; DISK_SECTORS]; N_TENANTS]      // overlay[t][s] is live iff dirty[t][s]
}
read(t, s)  = dirty[t][s] ? overlay[t][s] : template[s]   // clean sector falls through to the template
write(t, s) = overlay[t][s] = data; dirty[t][s] = true    // a write ALWAYS diverges into the overlay
```

Both properties hold by construction: `write` only ever mutates `overlay` (template-immutability), and
`overlay`/`dirty` are per-tenant rows (overlay-isolation). The store persists across the two block-phase
`Hypervisor` rebuilds — it is backend storage, not model state — which is what lets tenant 1 read the
template tenant 0 left pristine.

## Scope — real vs. synthesized (named for the audit)

- **Real (so a Linux virtio-blk driver works unchanged at the capstone):** the virtio-mmio v2 register
  file + `Status` handshake + `VIRTIO_F_VERSION_1` negotiation (identical to the Arc-3 console — the
  shared transport), the `virtio_blk_config { capacity }` config space, and the `virtio_blk_req` request
  protocol (`{ type, reserved, sector }` header + data buffer + status byte) over a split-virtqueue
  descriptor chain. Writing `Status=0` resets the device (virtio 1.x §2.1.1).
- **Synthesized (this arc):** the *drivers* — two hand-written guests. Phase 6 (tenant 0) reads sector 0
  (de-risks the chain + device-writable DMA + CoW-read), writes the poison payload to its overlay, and
  issues the un-granted negative. Phase 7 (tenant 1) reads sector 0 and must see the pristine template.
- Two sequential tenant phases: storage isolation is **orthogonal** to CPU multiplexing (Arcs 1/2 own
  temporal/spatial CPU isolation), so it gets its own witness rather than being entangled with a switch.

## Witnesses (all boot-test-asserted; the diamond in one boot)

| witness | marker |
| --- | --- |
| device identity (id=2) via trap-and-emulate | `virtio-blk device identified: … id=2 (block)` |
| `VIRTIO_F_VERSION_1` negotiated | `virtio-blk negotiation OK` |
| read served from the template (grant-checked, device-writable DMA) | `virtio-blk READ served sector 0 to tenant 0` + `baleen-blk-template-sector-0-pristine` |
| read round-trip (tenant 0) | `virtio-blk read round-trip OK: tenant 0 …` |
| write → CoW overlay | `virtio-blk WRITE by tenant 0 landed in its CoW overlay` |
| **template-immutability** (HV-side) | `virtio-blk template-immutability OK …` |
| grant negative (un-granted data buffer refused) | `virtio backend REFUSED un-granted access to Mfn 5` |
| **overlay-isolation** (tenant 1 reads pristine, distinct overlay) | `virtio-blk read round-trip OK: tenant 1 …` |
| the whole matrix | `VIRTIO-BLK TEST PASSED — writes hit the CoW overlay, template immutable, peer overlay isolated, un-granted access refused` |
| the poison never crosses | `FORBIDDEN_MARKERS` absent: `POISON-blk-guest0-write-must-not-cross` |

See `docs/AUDIT-6-VIRTIO-BLK-COW.md` for the per-dimension audit and the review pass (three spec-blind
auditors + empirical mutation testing).
