// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # virtio-mmio console — the ring is a proven grant (M5 Arc 3)
//!
//! A minimal but **spec-correct** virtio-mmio (v2, modern / `VIRTIO_F_VERSION_1`) **console** device
//! with a single TX split-virtqueue, emulated in EL2 as the backend of the control domain (`dom0`).
//! Arc 3's diamond is small and sharp: the shared memory a virtio device uses — the descriptor table,
//! the available ring, the used ring, and the data buffers — is **not** an unaudited hole punched into
//! the guest's isolation. Every byte the backend reads from or writes to guest memory is **authorized
//! by the proven `hv-core` grant** (`grant::authorizes(guest, dom0, mfn, writable)`): the guest owns
//! the ring frames and *grants* them to the backend, and an access to a frame the guest did **not**
//! grant is refused. The virtqueue *is* a grant.
//!
//! ## What is real vs. synthesized (named for the audit)
//!
//! - **Real (so a Linux virtio-console driver works unchanged at the capstone):** the virtio-mmio v2
//!   register file + its `Status` handshake, the `VIRTIO_F_VERSION_1` feature negotiation, and the
//!   **split virtqueue** layout (descriptor table / available ring / used ring, packed exactly as the
//!   virtio 1.x spec lays them out in guest memory).
//! - **Synthesized (this arc):** the *driver* — a hand-written guest that drives the mmio registers and
//!   builds one descriptor, standing in for Linux's virtio-mmio + virtio-console drivers (the real
//!   Linux guest is the Arc-5 capstone). **TX only** (guest → host console output); RX is deferred.
//!   One console device, one queue, one non-chained/non-indirect descriptor per notify.
//!
//! ## The trap-and-emulate transport (new metal capability)
//!
//! The device's mmio window ([`VIRTIO_MMIO_BASE`]`..+`[`VIRTIO_MMIO_SIZE`]) is deliberately left
//! **unmapped** in the guest's Stage-2, so a guest load/store to a device register faults to EL2 (a
//! Stage-2 data abort, `EC=0x24`). The metal decodes the abort syndrome — `FAR_EL2` gives the full
//! faulting address (Stage-1 is off, so guest VA == IPA), `ESR_EL2.ISS` gives the access size (`SAS`),
//! the target GP register (`SRT`), and direction (`WnR`) — services the register in [`mmio_read`] /
//! [`mmio_write`], writes any read result back into the guest's saved register frame, advances `ELR`
//! past the faulting instruction, and resumes. This is genuine trap-and-emulate of a device register
//! file, distinct from the pure isolation-fault probes of Arcs 5/0/2.

/// Guest **IPA** base of the console device's virtio-mmio register window. Matches the QEMU `virt`
/// virtio-mmio convention (so a future real Linux, told this address via DTB, needs no change) and sits
/// in its own Stage-2 `L1`/`L2` region well away from the guest image (`0x4000_0000`) and the model
/// data frames (`0x8000_0000`). Left unmapped in Stage-2 so every access traps.
pub const VIRTIO_MMIO_BASE: u64 = 0x0a00_0000;
/// Size of the mmio window (the v2 register file fits in `0x100`; console config space starts at
/// `0x100`). One `0x200` device slot, the standard virtio-mmio stride.
pub const VIRTIO_MMIO_SIZE: u64 = 0x200;

/// `true` iff `addr` falls in the console device's mmio window (so the data-abort handler routes it to
/// trap-and-emulate rather than the isolation-probe path).
pub fn in_mmio_window(addr: u64) -> bool {
    (VIRTIO_MMIO_BASE..VIRTIO_MMIO_BASE + VIRTIO_MMIO_SIZE).contains(&addr)
}

// ─── virtio-mmio v2 register offsets (from the mmio base) ──────────────────────────────────────────
mod reg {
    pub const MAGIC_VALUE: u64 = 0x000; // R  — 0x74726976 "virt"
    pub const VERSION: u64 = 0x004; // R  — 2 (modern)
    pub const DEVICE_ID: u64 = 0x008; // R  — 3 (console)
    pub const VENDOR_ID: u64 = 0x00c; // R  — "VBAL"
    pub const DEVICE_FEATURES: u64 = 0x010; // R  — features[DeviceFeaturesSel*32 ..]
    pub const DEVICE_FEATURES_SEL: u64 = 0x014; // W
    pub const DRIVER_FEATURES: u64 = 0x020; // W  — features[DriverFeaturesSel*32 ..]
    pub const DRIVER_FEATURES_SEL: u64 = 0x024; // W
    pub const QUEUE_SEL: u64 = 0x030; // W
    pub const QUEUE_NUM_MAX: u64 = 0x034; // R
    pub const QUEUE_NUM: u64 = 0x038; // W
    pub const QUEUE_READY: u64 = 0x044; // RW
    pub const QUEUE_NOTIFY: u64 = 0x050; // W
    pub const INTERRUPT_STATUS: u64 = 0x060; // R
    pub const INTERRUPT_ACK: u64 = 0x064; // W
    pub const STATUS: u64 = 0x070; // RW
    pub const QUEUE_DESC_LOW: u64 = 0x080; // W
    pub const QUEUE_DESC_HIGH: u64 = 0x084; // W
    pub const QUEUE_DRIVER_LOW: u64 = 0x090; // W  (available ring)
    pub const QUEUE_DRIVER_HIGH: u64 = 0x094; // W
    pub const QUEUE_DEVICE_LOW: u64 = 0x0a0; // W  (used ring)
    pub const QUEUE_DEVICE_HIGH: u64 = 0x0a4; // W
    pub const CONFIG_GENERATION: u64 = 0x0fc; // R
}

/// virtio-mmio identity constants.
pub const MAGIC: u32 = 0x7472_6976; // "virt" little-endian
pub const VERSION_V2: u32 = 2;
pub const DEVICE_ID_CONSOLE: u32 = 3;
pub const VENDOR: u32 = 0x4c41_4256; // "VBAL"

/// The single feature we require: `VIRTIO_F_VERSION_1` (bit 32) — modern, non-legacy. Advertised in
/// device-features word 1 (bits 32..63), so bit `0` of word 1.
pub const VIRTIO_F_VERSION_1_BIT: u32 = 32;
/// `VIRTIO_F_VERSION_1` as a mask within device-features **word 1**.
pub const VERSION_1_WORD1_MASK: u32 = 1 << (VIRTIO_F_VERSION_1_BIT - 32);

// Device `Status` bits (virtio 1.x §2.1) — the handshake the driver walks.
pub const STATUS_ACKNOWLEDGE: u32 = 1;
pub const STATUS_DRIVER: u32 = 2;
pub const STATUS_DRIVER_OK: u32 = 4;
pub const STATUS_FEATURES_OK: u32 = 8;

// ─── split-virtqueue in-memory layout (virtio 1.x §2.7) — the field offsets the backend parses ──────
//
// The driver programs the three ring base addresses (Desc/Driver/Device) via the queue registers; the
// backend reads them back and parses the rings at these sub-field offsets. It is layout-agnostic about
// where in guest memory the driver *placed* the rings (spec-correct) — only the internal field layout
// is fixed.

/// Bytes per `virtq_desc` = `{ le64 addr; le32 len; le16 flags; le16 next; }`.
pub const VIRTQ_DESC_SIZE: u64 = 16;
/// `virtq_avail` = `{ le16 flags; le16 idx; le16 ring[N]; }` — `idx` at +2, `ring` at +4.
pub const VIRTQ_AVAIL_IDX_OFF: u64 = 2;
pub const VIRTQ_AVAIL_RING_OFF: u64 = 4;
/// `virtq_used` = `{ le16 flags; le16 idx; virtq_used_elem ring[N]; }` with
/// `virtq_used_elem = { le32 id; le32 len; }` — `idx` at +2, `ring` at +4, 8 bytes/elem.
pub const VIRTQ_USED_IDX_OFF: u64 = 2;
pub const VIRTQ_USED_RING_OFF: u64 = 4;
pub const VIRTQ_USED_ELEM_SIZE: u64 = 8;

/// The maximum queue size the device supports (a power of two, per spec).
pub const QUEUE_NUM_MAX_VAL: u32 = 8;

/// The console device's mmio register state — the trap-and-emulate register file. All the values a
/// driver programs during negotiation live here; the queue-processing (Arc-3 steps 3-4) reads the ring
/// addresses back out.
///
/// `allow(dead_code)`: the register file is defined once as a coherent unit, but its fields are *read*
/// incrementally across Arc-3's steps — step 1 wires the identity registers, step 2 the negotiation
/// handshake, steps 3-4 the ring addresses. The allow is removed once every field is live (step 4).
#[allow(dead_code)]
pub struct VirtioConsole {
    /// `DeviceFeaturesSel` — which 32-bit word of the device features the driver is reading.
    pub device_features_sel: u32,
    /// `DriverFeaturesSel` — which 32-bit word of the driver features the driver is writing.
    pub driver_features_sel: u32,
    /// The driver's accepted feature words (index 0 = bits 0..31, index 1 = bits 32..63).
    pub driver_features: [u32; 2],
    /// `QueueSel` — the queue the queue-registers currently address (only queue 0 exists).
    pub queue_sel: u32,
    /// `QueueNum` — the negotiated ring size.
    pub queue_num: u32,
    /// `QueueReady` — set by the driver when the queue is live.
    pub queue_ready: u32,
    /// The split-virtqueue region guest addresses (IPAs) the driver programmed.
    pub queue_desc: u64,
    pub queue_driver: u64, // available ring
    pub queue_device: u64, // used ring
    /// `Status` — the device-status handshake byte the driver walks (ACK→DRIVER→FEATURES_OK→DRIVER_OK).
    pub status: u32,
    /// `InterruptStatus` — used-buffer-notification bit the backend raises (ACKed by the driver).
    pub interrupt_status: u32,
    /// The device's own view of the used ring's next index (how many buffers it has returned).
    pub used_idx: u16,
    /// The next available-ring index the backend has NOT yet consumed (its private cursor).
    pub last_avail_idx: u16,
}

impl VirtioConsole {
    /// The queue is live for processing iff the driver finished the handshake (`DRIVER_OK`) and marked
    /// the queue ready. The backend refuses to touch guest memory until both hold.
    pub fn queue_live(&self) -> bool {
        self.status & STATUS_DRIVER_OK != 0 && self.queue_ready == 1
    }
}

impl VirtioConsole {
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
        }
    }

    /// Service a driver **read** of the register at `offset` (relative to [`VIRTIO_MMIO_BASE`]). Returns
    /// the 32-bit register value (virtio-mmio registers are 32-bit). Step 1 wires the identity + a few
    /// negotiation registers; unknown offsets read as 0 (the spec's behaviour for reserved registers).
    pub fn mmio_read(&self, offset: u64) -> u32 {
        match offset {
            reg::MAGIC_VALUE => MAGIC,
            reg::VERSION => VERSION_V2,
            reg::DEVICE_ID => DEVICE_ID_CONSOLE,
            reg::VENDOR_ID => VENDOR,
            reg::DEVICE_FEATURES => {
                // Word 0: no features in bits 0..31. Word 1: VIRTIO_F_VERSION_1 (bit 32 → word-1 bit 0).
                if self.device_features_sel == 1 {
                    1 << (VIRTIO_F_VERSION_1_BIT - 32)
                } else {
                    0
                }
            }
            reg::QUEUE_NUM_MAX => QUEUE_NUM_MAX_VAL,
            reg::QUEUE_READY => self.queue_ready,
            reg::INTERRUPT_STATUS => self.interrupt_status,
            reg::STATUS => self.status,
            reg::CONFIG_GENERATION => 0,
            _ => 0,
        }
    }

    /// Service a driver **write** of `value` to the register at `offset`. Returns `true` iff this write
    /// was a `QueueNotify` (a kick) — the caller then runs the backend's queue processing (step 3).
    /// Step 1 records the negotiation registers; the queue-processing is wired in later steps.
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
                self.status = value;
                // When the driver sets FEATURES_OK, the device confirms it accepts the negotiated
                // features (virtio 1.x §3.1.1 step 6). We require VIRTIO_F_VERSION_1; if the driver did
                // not accept it, the device clears FEATURES_OK to signal rejection — the driver reads
                // Status back and must see it still set to proceed.
                if value & STATUS_FEATURES_OK != 0
                    && self.driver_features[1] & VERSION_1_WORD1_MASK == 0
                {
                    self.status &= !STATUS_FEATURES_OK;
                }
            }
            reg::INTERRUPT_ACK => self.interrupt_status &= !value,
            reg::QUEUE_NOTIFY => return true, // a kick — the caller processes the queue
            _ => {}
        }
        false
    }
}
