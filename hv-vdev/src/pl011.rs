// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The emulated PL011 register file
//!
//! The device the real-Linux guest believes it has. ③-a1 shrank the Stage-2 pass-through window
//! until `0x0900_0000` fell out of it, so a guest store there is a translation fault to EL2; this is
//! what services it.
//!
//! ## Why a PL011 and not virtio-console (the probe that inverted the obvious call)
//!
//! `hv-metal`'s `virtio` module already had a proven console with the ring as a grant, and reusing
//! it was the obvious move. It is **impossible** with an unmodified kernel: the shipped Alpine
//! `-virt` config has `CONFIG_VIRTIO_MMIO=m` — a module — and the initramfs carries no
//! `/lib/modules`, so there is no bus for the (built-in) `CONFIG_VIRTIO_CONSOLE=y` to attach to. A
//! console that appears only once userspace has loaded modules is not a console.
//! `CONFIG_SERIAL_AMBA_PL011=y` and `_CONSOLE=y` are both built in, so emulating the device the
//! guest already believes it has works with the stock kernel from the first `earlycon` byte — and
//! `earlycon=pl011,0x9000000` keeps working, which the virtio route would have cost. `guest.dts`
//! needs **no change at all**.
//!
//! ## What is real and what is not (named for the audit)
//!
//! - **Real:** the register file, its reset values, the access widths a real driver uses (Linux's
//!   `amba-pl011` does 16-bit `readw`/`writew` for `UPIO_MEM`, `earlycon` does a 32-bit `readl` of
//!   `FR` and an 8-bit `writeb` of `DR`, and the AMBA bus probe does 32-bit `readl` of the
//!   peripheral/PrimeCell ID registers), and the transmit path.
//! - **Not real, and stated rather than hidden:** **there is no receive**. `FR.RXFE` is permanently
//!   set and `DR` reads as zero. Delivering a received byte means delivering an *interrupt*, and
//!   this device has no line into the guest's GIC — ③-a2 built the injection path and pointed it at
//!   the timer, not at this. The shipped guest is non-interactive (its `/init` prints its markers
//!   and powers off), so nothing in the demo or the gate needs it; a human typing at `cargo xtask
//!   qemu-linux` still will not be heard.
//! - **No isolation content of its own.** This is the *transport* two guests will need, not a proof
//!   about them. Say what it is: the console had to stop being the machine's before two guests
//!   could each have one, and that is plumbing — the thesis content is in the Stage-2 refinement
//!   the guest's RAM already rests on.
//!
//! ## This model is TOTAL, which is a property worth naming
//!
//! Neither entry point can fail. An unimplemented offset reads as 0 and absorbs writes, which is the
//! TRM's behaviour for reserved space — so unlike the GIC there is no `Err` path and no fail-closed
//! theorem to state. What is proven instead is that no offset the guest can name makes it **panic**,
//! and that is not vacuous: the identification-register read converts an offset into an index into
//! a fixed eight-element array, and its bounds hold *only* because two range checks are exactly one
//! block wide.
//!
//! ## Provenance
//!
//! Register offsets, reset values and the peripheral/PrimeCell identification bytes are from the
//! **ARM PrimeCell UART (PL011) Technical Reference Manual** — the same published spec `hv-metal`'s
//! *driver* for the real device is written against, and the same spec-not-implementation hygiene
//! `CLEANROOM.md` requires.

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
/// always empty (see the module docs: no receive).
const FR_STATIC: u32 = (1 << 7) | (1 << 4);

/// `UARTRIS` bits: transmit-interrupt raw status (5). Set, because the TX FIFO really is below its
/// trigger level at all times. Nothing is ever *delivered* — this device has no line into the
/// guest's GIC — which is sound for the driver's TX path: `pl011_start_tx_pio` only arms `TXIM` if a
/// `pl011_tx_chars` call left the circular buffer non-empty, and with `FR.TXFF` always clear it
/// never does.
const RIS_STATIC: u32 = 1 << 5;

/// `UARTIFLS` reset value: RX and TX trigger levels both ½ (TRM reset value `0x12`).
const IFLS_RESET: u32 = 0x12;

/// `UARTPeriphID0..3` then `UARTPCellID0..3` (PL011 TRM): peripheral id `0x0014_1011` (part `0x011`,
/// designer `0x41` = Arm, revision 1) and the fixed PrimeCell id `0xb105_f00d`. A driver that does
/// not recognize these does not bind — the AMBA bus reads them before any UART register.
const ID: [u32; 8] = [0x11, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1];

/// The number of identification registers in each of the two blocks [`VirtPl011::read_id`] serves.
///
/// **Named rather than written as a literal `16`, because it is the reason that function is safe.**
/// `ID` has eight entries, four per block; a block is therefore `4 * 4` bytes wide, and a range
/// check even one word wider would index past the array. Deriving the width from `ID.len()` makes
/// the two agree by construction instead of by coincidence.
const ID_BLOCK_BYTES: u64 = 4 * (ID.len() as u64) / 2;

/// The emulated PL011's register file: what a driver programs and reads back.
///
/// **State a guest driver can observe, and nothing else.** The transmit path's evidence — bytes
/// relayed, registers trapped, whether a marker passed through — lives in the caller; see the crate
/// docs for why that separation is what makes this type's properties stateable.
///
/// None of these fields steers the transmit path, which is why a guest cannot mis-program its way
/// out of the emulation: `mmio_write` reports a `DR` byte to the caller regardless of `CR.UARTEN`,
/// `LCR_H`, or the baud divisors.
///
/// `Clone`/`PartialEq` exist **for the proofs** — see [`crate::gicv3::VirtGic`] for the reasoning.
#[derive(Clone, PartialEq, Eq)]
pub struct VirtPl011 {
    cr: u32,
    lcr_h: u32,
    ibrd: u32,
    fbrd: u32,
    ifls: u32,
    imsc: u32,
    ilpr: u32,
    dmacr: u32,
}

impl Default for VirtPl011 {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtPl011 {
    /// The device at reset (TRM reset values for the registers a driver reads back).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            cr: 0,
            lcr_h: 0,
            ibrd: 0,
            fbrd: 0,
            ifls: IFLS_RESET,
            imsc: 0,
            ilpr: 0,
            dmacr: 0,
        }
    }

    /// Service a guest **read** at `offset` (relative to the device's base), `bytes` wide.
    ///
    /// The register file is 32-bit; a narrower access takes the low lane of its aligned word, which
    /// is what a 16-bit `readw` of a 16-bit PL011 register means. Unimplemented offsets read as 0
    /// (the TRM's behaviour for reserved space).
    #[must_use]
    pub fn mmio_read(&self, offset: u64, bytes: u64) -> u64 {
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
    /// caller is what leaves this crate free of `unsafe`.
    #[must_use]
    pub fn mmio_write(&mut self, offset: u64, value: u64) -> Option<u8> {
        match offset {
            reg::DR => return Some(value as u8),
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
            _ => Self::read_id(offset),
        }
    }

    /// The peripheral / PrimeCell identification bytes, or 0 outside them.
    ///
    /// **The one place in this device where a guest-chosen offset becomes an array index.** The
    /// index is in range only because each block is [`ID_BLOCK_BYTES`] wide and `ID` holds exactly
    /// two blocks' worth; widening either range check by one word reads past the array.
    fn read_id(offset: u64) -> u32 {
        if (reg::PERIPH_ID0..reg::PERIPH_ID0 + ID_BLOCK_BYTES).contains(&offset)
            || (reg::PCELL_ID0..reg::PCELL_ID0 + ID_BLOCK_BYTES).contains(&offset)
        {
            let i = if offset < reg::PCELL_ID0 {
                (offset - reg::PERIPH_ID0) / 4
            } else {
                (ID.len() as u64) / 2 + (offset - reg::PCELL_ID0) / 4
            };
            ID[i as usize]
        } else {
            0
        }
    }
}

/// A rolling match of a fixed byte sequence over a stream — the transmit-path witness, kept as its
/// own type rather than as fields of [`VirtPl011`].
///
/// **Why it is here and not in the caller with the other counters.** The rest of the boot witness is
/// arithmetic a caller can do for itself: count the calls, count the relayed bytes. This one is not
/// — it indexes the needle with a cursor it maintains itself, and `needle[at]` is in bounds only
/// because `at` reaches `needle.len()` on the same statement that sets `saw`, which makes the next
/// call return early. That is a genuine inductive invariant, exactly the kind of thing an eye
/// skips and a proof does not, so it belongs under the fence even though its *purpose* is a witness.
///
/// The needle is required non-empty at construction. A zero-length needle would either index out of
/// bounds or silently never match, and a witness that silently never matches looks exactly like one
/// that legitimately did not fire.
pub struct NeedleMatcher {
    needle: &'static [u8],
    /// How much of `needle` the stream has matched so far.
    at: usize,
    /// Whether `needle` has passed through in full.
    saw: bool,
}

impl NeedleMatcher {
    /// A matcher for `needle`, which must be non-empty (checked at compile time when this is called
    /// in a `const` initializer, which is the intended use).
    #[must_use]
    pub const fn new(needle: &'static [u8]) -> Self {
        assert!(
            !needle.is_empty(),
            "a needle matcher needs a non-empty needle: an empty one can never fire, which is \
             indistinguishable from a witness that legitimately did not"
        );
        Self {
            needle,
            at: 0,
            saw: false,
        }
    }

    /// Advance the rolling match over one transmitted byte.
    pub fn feed(&mut self, byte: u8) {
        if self.saw {
            return;
        }
        if byte == self.needle[self.at] {
            self.at += 1;
            if self.at == self.needle.len() {
                self.saw = true;
            }
        } else {
            // Restart, allowing the mismatched byte to be the needle's own first byte.
            self.at = usize::from(byte == self.needle[0]);
        }
    }

    /// Whether the needle has passed through the stream in full.
    #[must_use]
    pub const fn saw(&self) -> bool {
        self.saw
    }
}
