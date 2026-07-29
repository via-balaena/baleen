// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The **emulated** PL011 the real-Linux guest drives (③-a1, feature `real-linux`)
//!
//! Until ③-a1 the real-Linux guest *owned* the machine's PL011: the pass-through device window ran
//! `0x0800_0000 .. 0x0a00_0000` (32 MiB), so `0x0900_0000` was mapped into the guest's Stage-2 and
//! every character the kernel printed was a store the guest made **directly to the hardware**. That
//! is fine for one guest and impossible for two: a UART is not a shareable resource, and
//! `linux.rs`'s own module doc named the pass-through model as the thing a second guest would break.
//!
//! So the window shrank to 16 MiB — `0x0800_0000 .. 0x0900_0000`, which still covers the whole
//! GICv3 (distributor **and** redistributor, whose region ends *exactly* at `0x0900_0000`) — and the
//! PL011 fell out of it. A guest access to `0x0900_0000` is now a Stage-2 translation fault to EL2,
//! and this module is what services it: a PL011 register file in EL2 memory, with the guest's
//! transmit bytes forwarded to the **real** UART.
//!
//! ## Why a PL011 and not virtio-console (the probe that inverted the obvious call)
//!
//! `crate::virtio` already has a proven console with the ring as a grant, and reusing it was the
//! obvious move. It is **impossible** with an unmodified kernel: the shipped Alpine `-virt` config
//! has `CONFIG_VIRTIO_MMIO=m` — a module — and this initramfs carries no `/lib/modules`, so there
//! is no bus for the (built-in) `CONFIG_VIRTIO_CONSOLE=y` to attach to. A console that appears only
//! once userspace has loaded modules is not a console. `CONFIG_SERIAL_AMBA_PL011=y` and
//! `_CONSOLE=y` are both built in, so emulating the device the guest already believes it has works
//! with the stock kernel from the first `earlycon` byte — and `earlycon=pl011,0x9000000` keeps
//! working, which the virtio route would have cost. `guest.dts` needs **no change at all**.
//!
//! ## What is real and what is not (named for the audit)
//!
//! - **Real:** the register file, its reset values, the access widths a real driver uses (Linux's
//!   `amba-pl011` does 16-bit `readw`/`writew` for `UPIO_MEM`, `earlycon` does a 32-bit `readl` of
//!   `FR` and an 8-bit `writeb` of `DR`, and the AMBA bus probe does 32-bit `readl` of the
//!   peripheral/PrimeCell ID registers), and the transmit path.
//! - **Not real, and stated rather than hidden:** **there is no receive**. `FR.RXFE` is permanently
//!   set and `DR` reads as zero, because delivering a received byte means delivering an
//!   *interrupt*, and this rung deliberately keeps `HCR_EL2.IMO = 0` — physical interrupts still go
//!   straight to the guest's EL1. Interrupt injection into a real Linux guest is ③-a2 (it reuses
//!   the already-proven vGIC list-register path of Arcs 7a–8b/III-3). The guest is non-interactive
//!   (its `/init` prints its markers and powers off), so nothing in the demo or the gate needs it —
//!   but a human typing at `cargo xtask qemu-linux` will not be heard until ③-a2.
//! - **No isolation content of its own.** This is the *transport* two guests will need, not a proof
//!   about them; ③-b (a second window, a second guest, each faulting on the peer's memory) is where
//!   the thesis content is. Say what it is: INTEGRATION, boot-witnessed.
//!
//! ## Provenance
//!
//! Register offsets, reset values and the peripheral/PrimeCell identification bytes are from the
//! **ARM PrimeCell UART (PL011) Technical Reference Manual** — the same published spec
//! [`crate::pl011`] (the *driver* for the real device) is written against, and the same
//! spec-not-implementation hygiene `CLEANROOM.md` requires.
//!
//! ## Unsafe
//!
//! **None in this module.** The device model is ordinary safe code over a plain struct; the one
//! `unsafe` in the path is the existing volatile MMIO in [`crate::pl011`], reached because
//! [`VirtPl011::mmio_write`] hands the caller a byte to transmit rather than touching hardware
//! itself.

/// Guest IPA base of the emulated PL011 — the address `guest.dts` already names
/// (`pl011@9000000`, `stdout-path`, and `earlycon=pl011,0x9000000`), unchanged by this rung.
pub(crate) const VPL011_BASE: u64 = 0x0900_0000;

/// Size of the register window — one 4 KiB page, matching the `reg` the DTB advertises. The AMBA
/// bus probe reads the identification registers at `size - 0x20 ..` , so this length is what puts
/// them at `0xfe0`.
pub(crate) const VPL011_SIZE: u64 = 0x1000;

// ─── the two structural facts this rung rests on, checked by the COMPILER ────────────────────────
//
// A boot marker can only witness what a boot exercises. These two are true or the build fails.

/// The emulated PL011 is at the address the metal's own console driver uses — i.e. the guest is
/// offered *the same device it had*, and `guest.dts` needs no edit. (If a future board moved the
/// UART, this is the line that would notice.)
const _: () = assert!(
    VPL011_BASE == crate::UART0_BASE as u64,
    "the emulated PL011 must sit at the machine's real PL011 address — guest.dts names it"
);

/// **The load-bearing one.** The pass-through device window must not COVER the PL011: if it did,
/// the guest's stores would land on the hardware, this emulator would never be entered, and every
/// existing marker in the real-Linux gate would still pass — a green boot that proves nothing about
/// the mechanism it is supposed to be witnessing. So the window ends where the PL011 begins, and
/// widening it back to the pre-③ 32 MiB breaks the build rather than silently restoring
/// pass-through.
const _: () = assert!(
    crate::stage2::windows().device_base + crate::stage2::windows().device_len <= VPL011_BASE,
    "the Stage-2 pass-through device window covers the PL011: the guest would drive the REAL UART \
     and the EL2 emulator would never be reached"
);

/// `true` iff `ipa` falls in the emulated PL011's window, so the real-Linux data-abort handler
/// routes it to trap-and-emulate rather than reporting an unexpected fault and parking.
pub(crate) fn in_window(ipa: u64) -> bool {
    (VPL011_BASE..VPL011_BASE + VPL011_SIZE).contains(&ipa)
}

// ─── PL011 register offsets (ARM PL011 TRM) ──────────────────────────────────────────────────────
mod reg {
    pub const DR: u64 = 0x000; // Data register (RW).
    pub const RSR_ECR: u64 = 0x004; // Receive status (R) / error clear (W).
    pub const FR: u64 = 0x018; // Flag register (R).
    pub const ILPR: u64 = 0x020; // IrDA low-power counter (RW).
    pub const IBRD: u64 = 0x024; // Integer baud-rate divisor (RW).
    pub const FBRD: u64 = 0x028; // Fractional baud-rate divisor (RW).
    pub const LCR_H: u64 = 0x02c; // Line control (RW).
    pub const CR: u64 = 0x030; // Control (RW).
    pub const IFLS: u64 = 0x034; // Interrupt FIFO level select (RW).
    pub const IMSC: u64 = 0x038; // Interrupt mask set/clear (RW).
    pub const RIS: u64 = 0x03c; // Raw interrupt status (R).
    pub const MIS: u64 = 0x040; // Masked interrupt status (R).
    pub const ICR: u64 = 0x044; // Interrupt clear (W).
    pub const DMACR: u64 = 0x048; // DMA control (RW).

    /// Peripheral identification `UARTPeriphID0..3` — `0xfe0`, `0xfe4`, `0xfe8`, `0xfec`.
    pub const PERIPH_ID0: u64 = 0xfe0;
    /// PrimeCell identification `UARTPCellID0..3` — `0xff0`, `0xff4`, `0xff8`, `0xffc`.
    pub const PCELL_ID0: u64 = 0xff0;
}

/// `UARTFR` bits: transmit FIFO empty (7) and receive FIFO empty (4). The constant flag word this
/// device reports — the TX FIFO is never full and never busy (a byte handed to the model is already
/// on its way out of the real UART by the time the guest's store retires), and the RX FIFO is
/// always empty (see the module docs: no receive until ③-a2).
const FR_STATIC: u32 = (1 << 7) | (1 << 4);

/// `UARTRIS` bits: transmit-interrupt raw status (5). Set, because the TX FIFO really is below its
/// trigger level at all times. Nothing is ever *delivered* — `HCR_EL2.IMO` is 0 and this device has
/// no line into the guest's GIC — which is sound for the driver's TX path: `pl011_start_tx_pio`
/// only arms `TXIM` if a `pl011_tx_chars` call left the circular buffer non-empty, and with
/// `FR.TXFF` always clear it never does.
const RIS_STATIC: u32 = 1 << 5;

/// `UARTIFLS` reset value: RX and TX trigger levels both ½ (TRM reset value `0x12`).
const IFLS_RESET: u32 = 0x12;

/// `UARTPeriphID0..3` then `UARTPCellID0..3` (PL011 TRM): peripheral id `0x0014_1011` (part `0x011`,
/// designer `0x41` = Arm, revision 1) and the fixed PrimeCell id `0xb105_f00d`. A driver that does
/// not recognize these does not bind — the AMBA bus reads them before any UART register.
const ID: [u32; 8] = [0x11, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

/// The userspace marker the emulator watches for in the guest's own transmit stream.
///
/// **This is what makes the witness discriminating** (design-lesson #24f, and #71 read from the
/// failure side). Every other marker in the real-Linux gate — `Linux version`, `Machine model`,
/// `BALEEN-STEP0-OK` — appears on the serial console whether the PL011 is emulated or passed
/// through, so none of them can tell the two apart. This one can: the bytes are counted *inside*
/// [`VirtPl011::mmio_write`], so the claim "the guest's console goes through EL2" is made by the
/// mechanism that would have to be running for it to be true.
const NEEDLE: &[u8] = b"BALEEN-STEP0-OK";

/// The emulated PL011's state: the registers a driver programs, plus the transmit-path evidence.
pub(crate) struct VirtPl011 {
    // ── the writable register file (read back as written; none of it steers the transmit path,
    //    which is why a guest cannot mis-program its way out of the emulation) ──
    cr: u32,
    lcr_h: u32,
    ibrd: u32,
    fbrd: u32,
    ifls: u32,
    imsc: u32,
    ilpr: u32,
    dmacr: u32,

    // ── the witness ──
    /// Register accesses trapped and serviced (reads and writes).
    traps: u64,
    /// Bytes the guest transmitted through `DR`, i.e. forwarded to the real UART.
    dr_writes: u64,
    /// How much of [`NEEDLE`] the transmit stream has matched so far (a rolling matcher).
    needle_at: usize,
    /// Whether [`NEEDLE`] has passed through this device in full.
    saw_needle: bool,
}

impl VirtPl011 {
    /// The device at reset (TRM reset values for the registers a driver reads back).
    pub(crate) const fn new() -> Self {
        Self {
            cr: 0,
            lcr_h: 0,
            ibrd: 0,
            fbrd: 0,
            ifls: IFLS_RESET,
            imsc: 0,
            ilpr: 0,
            dmacr: 0,
            traps: 0,
            dr_writes: 0,
            needle_at: 0,
            saw_needle: false,
        }
    }

    /// Service a guest **read** at `offset` (relative to [`VPL011_BASE`]), `bytes` wide.
    ///
    /// The register file is 32-bit; a narrower access takes the low lane of its aligned word, which
    /// is what a 16-bit `readw` of a 16-bit PL011 register means. Unimplemented offsets read as 0
    /// (the TRM's behaviour for reserved space).
    pub(crate) fn mmio_read(&mut self, offset: u64, bytes: u64) -> u64 {
        self.traps += 1;
        let word = self.read_word(offset & !3) as u64;
        let lane = (offset & 3) * 8;
        let mask: u64 = match bytes {
            1 => 0xff,
            2 => 0xffff,
            _ => 0xffff_ffff,
        };
        (word >> lane) & mask
    }

    /// Service a guest **write** of `value` at `offset`. Returns `Some(byte)` iff the write was to
    /// `DR` — the caller then puts that byte on the real UART. Keeping the hardware poke in the
    /// caller is what leaves this module free of `unsafe`.
    #[must_use]
    pub(crate) fn mmio_write(&mut self, offset: u64, value: u64) -> Option<u8> {
        self.traps += 1;
        match offset {
            reg::DR => {
                let byte = value as u8;
                self.dr_writes += 1;
                self.match_needle(byte);
                return Some(byte);
            }
            reg::RSR_ECR => {} // error clear: this device raises no receive errors.
            reg::ILPR => self.ilpr = value as u32,
            reg::IBRD => self.ibrd = value as u32,
            reg::FBRD => self.fbrd = value as u32,
            reg::LCR_H => self.lcr_h = value as u32,
            reg::CR => self.cr = value as u32,
            reg::IFLS => self.ifls = value as u32,
            reg::IMSC => self.imsc = value as u32,
            // Interrupt clear. Nothing to clear: the only raw status this device asserts is TX,
            // which is a level (the FIFO really is empty) and so is not clearable — exactly as on
            // the real device.
            reg::ICR => {}
            reg::DMACR => self.dmacr = value as u32,
            _ => {} // reserved / read-only: writes are dropped, as on the real device.
        }
        None
    }

    /// The 32-bit value of the register at an aligned `offset`.
    fn read_word(&self, offset: u64) -> u32 {
        match offset {
            reg::DR => 0, // RX FIFO permanently empty; a read yields no data and no error bits.
            reg::RSR_ECR => 0,
            reg::FR => FR_STATIC,
            reg::ILPR => self.ilpr,
            reg::IBRD => self.ibrd,
            reg::FBRD => self.fbrd,
            reg::LCR_H => self.lcr_h,
            reg::CR => self.cr,
            reg::IFLS => self.ifls,
            reg::IMSC => self.imsc,
            reg::RIS => RIS_STATIC,
            reg::MIS => RIS_STATIC & self.imsc,
            reg::DMACR => self.dmacr,
            _ => self.read_id(offset),
        }
    }

    /// The peripheral / PrimeCell identification bytes, or 0 outside them.
    fn read_id(&self, offset: u64) -> u32 {
        if (reg::PERIPH_ID0..reg::PERIPH_ID0 + 16).contains(&offset)
            || (reg::PCELL_ID0..reg::PCELL_ID0 + 16).contains(&offset)
        {
            let i = if offset < reg::PCELL_ID0 {
                (offset - reg::PERIPH_ID0) / 4
            } else {
                4 + (offset - reg::PCELL_ID0) / 4
            };
            ID[i as usize]
        } else {
            0
        }
    }

    /// Advance the rolling match of [`NEEDLE`] over the transmitted byte stream.
    fn match_needle(&mut self, byte: u8) {
        if self.saw_needle {
            return;
        }
        if byte == NEEDLE[self.needle_at] {
            self.needle_at += 1;
            if self.needle_at == NEEDLE.len() {
                self.saw_needle = true;
            }
        } else {
            // Restart, allowing the mismatched byte to be the needle's own first byte.
            self.needle_at = usize::from(byte == NEEDLE[0]);
        }
    }

    /// The witness this device produces: the guest's console output reached the serial line
    /// **through EL2**, evidenced by userspace's own marker having passed through `DR` here.
    ///
    /// Returns `(ok, traps, dr_writes)`. `ok` is false — and the boot says so by name — if the
    /// emulator was never entered (the window is passed through again) or was entered but never
    /// carried the guest's userspace output (the transmit path is broken).
    pub(crate) fn witness(&self) -> (bool, u64, u64) {
        (
            self.saw_needle && self.dr_writes > 0,
            self.traps,
            self.dr_writes,
        )
    }
}
