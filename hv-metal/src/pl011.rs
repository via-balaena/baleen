// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # PL011 UART driver — the metal layer's diagnostic console
//!
//! Arc 1 of M3 (see `docs/ROADMAP.md`): turn Arc 0's raw one-byte poke into a *proper* PL011
//! console — the substrate every later metal arc reports through (exception decode, the
//! `CurrentEL` readout, `hv-core` dispatch results). It does three things Arc 0 did not:
//!
//! 1. **Initializes** the UART into a known state (8N1, FIFOs on, TX enabled) rather than
//!    inheriting whatever reset — or QEMU's defaults — happened to leave.
//! 2. **Gates every write** on the TX-FIFO-not-full flag, so output cannot be silently dropped
//!    under load (Arc 0's blast-and-hope only survived because QEMU's FIFO never fills).
//! 3. Exposes [`core::fmt::Write`], so callers can `write!`/`writeln!` formatted diagnostics.
//!
//! ## Contract
//!
//! - **Property:** after [`Pl011::init`], the UART is in a known 8N1 + FIFO-enabled, TX-enabled
//!   state, and every byte handed to the console is transmitted **in order, none dropped** — each
//!   write spins until the TX FIFO has room ([`FR_TXFF`] clear).
//! - **Check:** the CI boot-test (`hv-metal/boot-test.sh`) asserts the banner reaches the serial
//!   console — end-to-end evidence the init + gated-write + `fmt` path all work.
//! - **Scope:** *plumbing / refines* — a diagnostic substrate with **no isolation content**. A
//!   green boot attests the console works, nothing about the hypervisor (`docs/QEMU-AND-METAL.md`).
//!
//! ## Provenance
//!
//! Register layout and the disable → configure → enable programming sequence are taken from the
//! **ARM PrimeCell UART (PL011) Technical Reference Manual** — a published hardware spec. This is
//! the spec-not-implementation hygiene `CLEANROOM.md` requires, applied to standard hardware.
//!
//! ## Unsafe
//!
//! The entire `unsafe` surface is 32-bit volatile MMIO to the fixed PL011 register block. The
//! base-validity precondition is asserted once, at [`Pl011::new`] (the safety invariant); the
//! internal register accessors rely on it. Arc 0/1 run with the MMU off, identity-mapped, so the
//! device address is directly valid.

use core::fmt;
use core::ptr;

// PL011 register offsets from the device base (ARM PL011 TRM). All registers are 32-bit.
const UARTDR: usize = 0x00; // Data register: write the low byte to transmit.
const UARTFR: usize = 0x18; // Flag register.
const UARTIBRD: usize = 0x24; // Integer baud-rate divisor.
const UARTFBRD: usize = 0x28; // Fractional baud-rate divisor.
const UARTLCR_H: usize = 0x2C; // Line control.
const UARTCR: usize = 0x30; // Control.
const UARTIMSC: usize = 0x38; // Interrupt mask set/clear.
const UARTICR: usize = 0x44; // Interrupt clear.

/// Flag register: transmit FIFO full. The gate — a write must wait until this is clear.
const FR_TXFF: u32 = 1 << 5;
/// Flag register: UART busy transmitting. Cleared once the shift register drains.
const FR_BUSY: u32 = 1 << 3;

/// Line control: enable transmit/receive FIFOs.
const LCR_H_FEN: u32 = 1 << 4;
/// Line control: 8-bit word length (`WLEN` = 0b11 in bits 6:5).
const LCR_H_WLEN_8: u32 = 0b11 << 5;

/// Control: UART enable.
const CR_UARTEN: u32 = 1 << 0;
/// Control: transmit enable.
const CR_TXE: u32 = 1 << 8;
/// Control: receive enable.
const CR_RXE: u32 = 1 << 9;

/// Clear-all mask for the interrupt-clear register (all 11 defined interrupt sources).
const ICR_ALL: u32 = 0x7FF;

// Baud divisors for 115200 baud assuming the QEMU `virt` PL011 clock (`UARTCLK` = 24 MHz):
//   divisor = 24_000_000 / (16 * 115200) = 13.0208…  → IBRD = 13, FBRD = round(0.0208 * 64) = 1.
// NOTE: QEMU's PL011 model does not implement baud timing — these are **inert under emulation**
// (output is identical whichever divisors are programmed). They are set for TRM-faithful init and
// fidelity toward real hardware; the real SoC `UARTCLK` is a later-hardware concern, not this one.
const IBRD_115200: u32 = 13;
const FBRD_115200: u32 = 1;

/// A PL011 UART at a fixed MMIO base.
///
/// Zero owned state beyond the base pointer — the device *is* the state. Cheap to construct a
/// fresh handle wherever one is needed (e.g. the panic handler), given the base is a real PL011.
pub struct Pl011 {
    base: *mut u32,
}

impl Pl011 {
    /// Create a handle over the PL011 at `base`.
    ///
    /// # Safety
    /// `base` must be the base address of a real PL011 register block that stays mapped for the
    /// lifetime of the handle. On the QEMU `virt` machine that is `0x0900_0000`, always mapped,
    /// and Arc 0/1 run identity-mapped with the MMU off. This precondition is the driver's safety
    /// invariant; every register access below relies on it rather than re-checking.
    pub const unsafe fn new(base: usize) -> Self {
        Self {
            base: base as *mut u32,
        }
    }

    /// Read a 32-bit register at `offset`.
    fn read(&self, offset: usize) -> u32 {
        // SAFETY: `offset` is a fixed in-range PL011 register offset; `self.base` is a real,
        // mapped PL011 block by the `new` precondition. `add` stays within the device window.
        unsafe { ptr::read_volatile(self.base.byte_add(offset)) }
    }

    /// Write a 32-bit register at `offset`.
    fn write(&self, offset: usize, value: u32) {
        // SAFETY: as `read` — fixed in-range offset over a real, mapped PL011 block.
        unsafe { ptr::write_volatile(self.base.byte_add(offset), value) };
    }

    /// Program the UART into a known state: 8N1, FIFOs enabled, TX+RX enabled.
    ///
    /// Follows the TRM sequence: disable, drain any in-flight transmission, set baud, commit line
    /// control, clear pending interrupts, then enable. Idempotent — safe to call again on a fresh
    /// handle (the panic handler does not rely on it having run).
    pub fn init(&self) {
        // Disable the UART before reconfiguring line control / baud (required by the TRM).
        self.write(UARTCR, 0);
        // Let any byte already in the shift register finish before we touch the config.
        while self.read(UARTFR) & FR_BUSY != 0 {}

        // Baud (inert under QEMU; see the divisor constants). LCR_H must be written after the
        // divisors — the LCR_H write latches the new baud.
        self.write(UARTIBRD, IBRD_115200);
        self.write(UARTFBRD, FBRD_115200);
        self.write(UARTLCR_H, LCR_H_FEN | LCR_H_WLEN_8);

        // Poll-only console: mask all interrupts and clear anything pending from reset.
        self.write(UARTIMSC, 0);
        self.write(UARTICR, ICR_ALL);

        // Enable the UART with transmit and receive.
        self.write(UARTCR, CR_UARTEN | CR_TXE | CR_RXE);
    }

    /// Transmit one byte, waiting for room in the TX FIFO first (never drops).
    pub fn put(&self, byte: u8) {
        while self.read(UARTFR) & FR_TXFF != 0 {}
        self.write(UARTDR, byte as u32);
    }

    /// Transmit a string, translating `\n` to `\r\n` so output renders correctly on a real serial
    /// terminal (QEMU's stdout tolerates a bare `\n`, but a hardware terminal needs the CR).
    pub fn write_bytes(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.put(b'\r');
            }
            self.put(byte);
        }
    }
}

impl fmt::Write for Pl011 {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_bytes(s);
        Ok(())
    }
}
