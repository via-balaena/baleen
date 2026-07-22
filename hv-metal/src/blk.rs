// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # virtio-blk + copy-on-write template storage (M5 Arc 4)
//!
//! A minimal but **spec-correct** virtio-mmio (v2, modern / `VIRTIO_F_VERSION_1`) **block** device
//! (`DeviceID` 2), backed by a **read-only template** and a **per-tenant copy-on-write overlay**. It
//! extends Arc 3's grant-gated virtqueue backend two ways — the block request is a **descriptor chain**
//! (`virtio_blk_req` header + a data buffer + a status byte, linked by `VIRTQ_DESC_F_NEXT`), and the
//! data buffer of a *read* is **device-writable** (`VIRTQ_DESC_F_WRITE`), so the backend does a
//! grant-checked **write** into guest memory (Arc 3 was device-read TX only).
//!
//! ## The diamond (Audit #6) — two orthogonal isolation surfaces
//!
//! - **Guest-memory isolation (grant-anchored, a regression of Arc 3):** every backend touch of guest
//!   memory across the chain — header, data buffer, status byte, used ring — is authorized by the proven
//!   `hv-core` grant ([`crate::guest`]'s `backend_authorize`). An un-granted descriptor is refused.
//! - **Disk isolation (the new Arc-4 content):** a guest's **write** lands in *its* overlay, never the
//!   template ([`BlkDisk::write`] only ever mutates `overlay`); a second tenant reading the sector the
//!   first poisoned sees the **pristine template** ([`BlkDisk::read`] falls through to `template` for any
//!   sector the tenant has not written); and the two tenants' overlays are **distinct storage, never
//!   aliased** (separate `overlay[tenant]` rows). *template-immutability* + *overlay-isolation*.
//!
//! ## The seam split (design-lesson #31d)
//!
//! The **disk** (template + overlays) is **backend/device-model storage** — it lives in a static owned
//! by the EL2 backend and is **never mapped into any guest's Stage-2**, so no guest can reach it
//! directly (unreachable by construction, Arc 2's distinct-PA argument at the device layer). A guest
//! reaches the disk **only** through the grant-mediated DMA descriptors — exactly as real virtio-blk. So
//! the CoW logic is device-model content proven by construction + witness + mutation, while every access
//! to *guest* memory stays anchored to the proven grant. This is the **disposable-from-template**
//! primitive the Arc-6 thesis (a disposable is a CoW overlay on a shared RO template) cashes in.
//!
//! ## What is real vs. synthesized (named for the audit)
//!
//! - **Real (so a Linux virtio-blk driver works unchanged at the capstone):** the virtio-mmio v2
//!   register file + `Status` handshake + `VIRTIO_F_VERSION_1` negotiation (identical to the Arc-3
//!   console), the `virtio_blk_config { capacity }` config space, and the `virtio_blk_req` request
//!   protocol over a split virtqueue **descriptor chain**.
//! - **Synthesized (this arc):** the *driver* — hand-written guests that drive one read and one write.

use crate::virtio::{
    reg, MAGIC, STATUS_DRIVER_OK, STATUS_FEATURES_OK, VENDOR, VERSION_1_WORD1_MASK, VERSION_V2,
    VIRTIO_F_VERSION_1_BIT,
};

/// virtio-blk `DeviceID` (virtio 1.x §5.2). The console was 3; the block device is 2.
pub const DEVICE_ID_BLK: u32 = 2;

// ─── virtio-blk request protocol (virtio 1.x §5.2.6) ─────────────────────────────────────────────
//
// A request is a chain of (usually) three descriptors:
//   desc0: `struct virtio_blk_req { le32 type; le32 reserved; le64 sector; }` — device-READABLE (16 B)
//   desc1: the data buffer, `sector_count * 512` bytes — device-WRITABLE for a read (`T_IN`),
//          device-READABLE for a write (`T_OUT`)
//   desc2: `u8 status` — device-WRITABLE (the backend writes `VIRTIO_BLK_S_OK`)

/// Request type: **read** — the device writes the sector into the guest's (device-writable) buffer.
pub const VIRTIO_BLK_T_IN: u32 = 0;
/// Request type: **write** — the device reads the guest's buffer into the sector.
pub const VIRTIO_BLK_T_OUT: u32 = 1;

/// Status byte: request completed OK.
pub const VIRTIO_BLK_S_OK: u8 = 0;
/// Status byte: an I/O error (e.g. the backend refused an un-granted data buffer).
pub const VIRTIO_BLK_S_IOERR: u8 = 1;

/// `virtq_desc.flags` bit — this descriptor chains to `desc.next`.
pub const VIRTQ_DESC_F_NEXT: u16 = 1;
/// `virtq_desc.flags` bit — this descriptor is **device-writable** (the backend writes into it).
pub const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Bytes per virtio block sector (the virtio-blk unit; `capacity` is counted in these).
pub const SECTOR_SIZE: usize = 512;
/// Bytes of the `virtio_blk_req` header (`type` + `reserved` + `sector`).
pub const BLK_HDR_SIZE: u64 = 16;
/// Field offset of `sector` (the `le64`) within the header.
pub const BLK_HDR_SECTOR_OFF: u64 = 8;
/// Config-space offset (from the mmio base) of `virtio_blk_config.capacity` (a `le64`, at config +0).
pub const BLK_CONFIG_CAPACITY: u64 = 0x100;

// ─── the copy-on-write disk store ────────────────────────────────────────────────────────────────

/// Number of sectors the template (and each overlay) holds — a tiny disk, enough for the witness.
pub const DISK_SECTORS: usize = 4;
/// Number of independent tenants (per-guest overlays) the disk supports. Two is the smallest that can
/// witness *overlay-isolation* (tenant 0 writes, tenant 1 reads and must see the pristine template).
pub const N_TENANTS: usize = 2;

/// **The copy-on-write disk — the heart of Arc 4.** One shared **read-only template** plus one
/// **writable overlay per tenant**. A read of sector `s` by tenant `t` returns the overlay's copy iff
/// the tenant has written it (`dirty[t][s]`), else the template — so a clean sector *falls through* to
/// the shared template, and a written sector *diverges* into the tenant's private overlay. A write
/// **only ever** mutates the overlay and sets the dirty bit; the template is written **once** at seed
/// time and never again. Both isolation properties hold by construction:
///
/// - *template-immutability* — [`write`](Self::write) touches only `overlay`, so no request path can
///   mutate `template` after seeding.
/// - *overlay-isolation* — `overlay[t]` and `dirty[t]` are per-tenant rows, so one tenant's writes are
///   invisible to another's reads, and the overlays are distinct storage (never aliased).
///
/// The store lives in a static owned by the EL2 backend (never in a guest Stage-2), so a guest can only
/// reach it through the grant-mediated DMA descriptors the backend services.
pub struct BlkDisk {
    /// The shared golden image — written once at seed time, read-only thereafter.
    template: [[u8; SECTOR_SIZE]; DISK_SECTORS],
    /// Per-tenant copy-on-write overlays; `overlay[t][s]` is live iff `dirty[t][s]`.
    overlay: [[[u8; SECTOR_SIZE]; DISK_SECTORS]; N_TENANTS],
    /// `dirty[t][s]` == the tenant has written sector `s` (so reads see the overlay, not the template).
    dirty: [[bool; DISK_SECTORS]; N_TENANTS],
}

impl BlkDisk {
    pub const fn new() -> Self {
        Self {
            template: [[0; SECTOR_SIZE]; DISK_SECTORS],
            overlay: [[[0; SECTOR_SIZE]; DISK_SECTORS]; N_TENANTS],
            dirty: [[false; DISK_SECTORS]; N_TENANTS],
        }
    }

    /// Seed a template sector with `bytes` (truncated / zero-padded to a sector). Called **once**, before
    /// any tenant runs; the template is read-only afterward.
    pub fn seed_template(&mut self, sector: usize, bytes: &[u8]) {
        let dst = &mut self.template[sector];
        *dst = [0; SECTOR_SIZE];
        let n = bytes.len().min(SECTOR_SIZE);
        dst[..n].copy_from_slice(&bytes[..n]);
    }

    /// **The CoW read.** Return the sector `t` sees: its overlay copy if it has written the sector, else
    /// the pristine template. This is the *fall-through* that makes a clean sector shared and a written
    /// sector private.
    pub fn read(&self, tenant: usize, sector: usize) -> &[u8; SECTOR_SIZE] {
        if self.dirty[tenant][sector] {
            &self.overlay[tenant][sector]
        } else {
            &self.template[sector]
        }
    }

    /// **The CoW write.** Copy `bytes` into tenant `t`'s overlay for `sector` and mark it dirty. The
    /// template is **never** touched — a write always diverges into the private overlay.
    pub fn write(&mut self, tenant: usize, sector: usize, bytes: &[u8]) {
        let dst = &mut self.overlay[tenant][sector];
        *dst = [0; SECTOR_SIZE];
        let n = bytes.len().min(SECTOR_SIZE);
        dst[..n].copy_from_slice(&bytes[..n]);
        self.dirty[tenant][sector] = true;
    }

    /// The template sector's backing, read **directly** (bypassing the CoW fall-through) — for the
    /// HV-side *template-immutability* witness (confirm a guest write never reached the template).
    pub fn template_sector(&self, sector: usize) -> &[u8; SECTOR_SIZE] {
        &self.template[sector]
    }

    /// A tenant's overlay sector backing, read **directly** — for the overlay-landed witness (tenant 0's
    /// write is here, not the template).
    pub fn overlay_sector(&self, tenant: usize, sector: usize) -> &[u8; SECTOR_SIZE] {
        &self.overlay[tenant][sector]
    }

    /// Address of a tenant's overlay sector backing — for the *overlay-isolation* witness that the two
    /// tenants' overlays are **distinct storage, never aliased**.
    pub fn overlay_ptr(&self, tenant: usize, sector: usize) -> *const u8 {
        self.overlay[tenant][sector].as_ptr()
    }
}

/// The virtio-blk device's mmio register state — the trap-and-emulate register file. Mirrors the Arc-3
/// console's [`crate::virtio::VirtioConsole`] register file (the shared virtio-mmio v2 transport: the
/// same identity/feature/status/queue registers, reusing [`crate::virtio::reg`] offsets), differing only
/// in the `DeviceID` (2, not 3) and the `virtio_blk_config.capacity` config space it exposes at +0x100.
pub struct VirtioBlk {
    pub device_features_sel: u32,
    pub driver_features_sel: u32,
    pub driver_features: [u32; 2],
    pub queue_sel: u32,
    pub queue_num: u32,
    pub queue_ready: u32,
    pub queue_desc: u64,
    pub queue_driver: u64, // available ring
    pub queue_device: u64, // used ring
    pub status: u32,
    pub interrupt_status: u32,
    pub used_idx: u16,
    pub last_avail_idx: u16,
    /// The device's advertised capacity, in 512-byte sectors (read via the config space).
    pub capacity: u64,
}

impl VirtioBlk {
    pub const fn new() -> Self {
        Self {
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: [0; 2],
            queue_sel: 0,
            queue_num: 0,
            queue_ready: 0,
            queue_desc: 0,
            queue_driver: 0,
            queue_device: 0,
            status: 0,
            interrupt_status: 0,
            used_idx: 0,
            last_avail_idx: 0,
            capacity: DISK_SECTORS as u64,
        }
    }

    /// The queue is live for processing iff the driver finished the handshake (`DRIVER_OK`) and marked
    /// the queue ready. The backend refuses to touch guest memory until both hold. (Mirrors the console.)
    pub fn queue_live(&self) -> bool {
        self.status & STATUS_DRIVER_OK != 0 && self.queue_ready == 1
    }

    /// Service a driver **read** of the register at `offset`. Identity + negotiation registers mirror the
    /// console; additionally the `virtio_blk_config.capacity` config space is exposed at +0x100/+0x104.
    pub fn mmio_read(&self, offset: u64) -> u32 {
        match offset {
            reg::MAGIC_VALUE => MAGIC,
            reg::VERSION => VERSION_V2,
            reg::DEVICE_ID => DEVICE_ID_BLK,
            reg::VENDOR_ID => VENDOR,
            reg::DEVICE_FEATURES => {
                // Only VIRTIO_F_VERSION_1 (bit 32 → word-1 bit 0); no blk-specific features negotiated.
                if self.device_features_sel == 1 {
                    1 << (VIRTIO_F_VERSION_1_BIT - 32)
                } else {
                    0
                }
            }
            reg::QUEUE_NUM_MAX => crate::virtio::QUEUE_NUM_MAX_VAL,
            reg::QUEUE_READY => self.queue_ready,
            reg::INTERRUPT_STATUS => self.interrupt_status,
            reg::STATUS => self.status,
            reg::CONFIG_GENERATION => 0,
            // virtio_blk_config.capacity (le64) at config +0 (mmio +0x100), low then high word.
            BLK_CONFIG_CAPACITY => self.capacity as u32,
            o if o == BLK_CONFIG_CAPACITY + 4 => (self.capacity >> 32) as u32,
            _ => 0,
        }
    }

    /// Service a driver **write** of `value` to the register at `offset`. Returns `true` iff this write
    /// was a `QueueNotify` (a kick) — the caller then runs the backend's block-request processing.
    /// Identical negotiation/queue-register handling to the console (the shared transport).
    #[must_use]
    pub fn mmio_write(&mut self, offset: u64, value: u32) -> bool {
        match offset {
            reg::DEVICE_FEATURES_SEL => self.device_features_sel = value,
            reg::DRIVER_FEATURES_SEL => self.driver_features_sel = value,
            reg::DRIVER_FEATURES => {
                let idx = (self.driver_features_sel & 1) as usize;
                self.driver_features[idx] = value;
            }
            reg::QUEUE_SEL => self.queue_sel = value,
            reg::QUEUE_NUM => self.queue_num = value,
            reg::QUEUE_READY => self.queue_ready = value,
            reg::QUEUE_DESC_LOW => {
                self.queue_desc = (self.queue_desc & !0xffff_ffff) | value as u64
            }
            reg::QUEUE_DESC_HIGH => {
                self.queue_desc = (self.queue_desc & 0xffff_ffff) | ((value as u64) << 32)
            }
            reg::QUEUE_DRIVER_LOW => {
                self.queue_driver = (self.queue_driver & !0xffff_ffff) | value as u64
            }
            reg::QUEUE_DRIVER_HIGH => {
                self.queue_driver = (self.queue_driver & 0xffff_ffff) | ((value as u64) << 32)
            }
            reg::QUEUE_DEVICE_LOW => {
                self.queue_device = (self.queue_device & !0xffff_ffff) | value as u64
            }
            reg::QUEUE_DEVICE_HIGH => {
                self.queue_device = (self.queue_device & 0xffff_ffff) | ((value as u64) << 32)
            }
            reg::STATUS => {
                // Writing 0 resets the device (virtio 1.x §2.1.1): drop the negotiated queue and the
                // backend's private ring cursors so a fresh driver starts clean (a real Linux driver
                // writes Status=0 on probe; here it also stops a prior tenant's cursors leaking in).
                if value == 0 {
                    *self = Self::new();
                    return false;
                }
                self.status = value;
                // Reject the handshake if the driver did not accept VIRTIO_F_VERSION_1 (same as console).
                if value & STATUS_FEATURES_OK != 0
                    && self.driver_features[1] & VERSION_1_WORD1_MASK == 0
                {
                    self.status &= !STATUS_FEATURES_OK;
                }
            }
            reg::INTERRUPT_ACK => self.interrupt_status &= !value,
            reg::QUEUE_NOTIFY => return true, // a kick — the caller processes the block queue
            _ => {}
        }
        false
    }
}
