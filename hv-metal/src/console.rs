// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The one serial line, multiplexed between guests (③-b2b-ii-a, feature `real-linux`)
//!
//! ## Why this exists — the machine has one UART and is about to have two kernels
//!
//! Since ③-a1 each guest drives its **own** emulated PL011 ([`crate::vpl011`]), and
//! [`crate::linux`] relays every transmitted byte to the real one. That relay is per-*byte*: a guest
//! store to `DR` is a Stage-2 data abort, one byte per trap. With one guest that is invisible. With
//! two, EL2 preempts at a timer tick that can land **between any two bytes of a line**, so the two
//! kernels' output interleaves character by character and the serial log stops containing whole
//! lines at all.
//!
//! That is not cosmetic. The real-Linux gate is `xtask::LINUX_MARKERS` — substring matching over
//! that log — so a shredded line means `Linux version 6.18.` simply is not present, and the gate
//! goes red for a boot that was entirely correct. **Byte-interleaving would have made the arc's
//! headline unassertable.**
//!
//! So EL2 buffers each guest's transmit stream to a newline and emits whole lines, tagged.
//!
//! ## The tag is EL2's claim, not the guest's
//!
//! `[dom N] ` is derived from **which model instance received the byte** — [`crate::linux`] indexes
//! the per-guest [`crate::vpl011::DeployedPl011`] by the running slot, and that index is what
//! reaches [`GuestConsole::put`]. Nothing in the guest's own output contributes to it.
//!
//! This matters because the two guests run the **same initramfs**: `guest-init.sh` prints
//! `BALEEN-STEP0-OK` for whichever kernel is executing it, so guest-supplied content cannot tell the
//! two apart. It is the reason the ③-b2b-ii headline marker is a *tag plus content* pair rather than
//! either half alone — see `xtask::LINUX_MARKERS`.
//!
//! ## Honest limits
//!
//! * A line longer than [`LINE_CAP`] is emitted in pieces, each separately tagged — so EL2 inserts a
//!   newline the guest did not write. Kernel and busybox lines are far shorter; the cap exists so a
//!   guest cannot make EL2 buffer without bound, not because splitting is free.
//! * The trailing `\r` a tty's `ONLCR` puts before every `\n` is stripped on emission, and EL2 emits
//!   its own `\r\n`. So the bytes on the wire are not byte-for-byte the guest's — the *line content*
//!   is, which is what the markers assert.
//! * Interleaving with **hv-metal's own** diagnostics is untouched: those go straight to
//!   [`crate::pl011::Pl011`] and can land between two guest lines, never inside one.
//!
//! ## Unsafe
//!
//! **None.** The bytes go out through [`crate::pl011::Pl011`], where the volatile MMIO already
//! lives.

use core::fmt::Write;

use crate::linux::{slot_dom, NUM_GUESTS};
use crate::pl011::Pl011;

/// Longest guest console line EL2 will hold before emitting it unterminated.
///
/// A bound rather than a guess: without one, a guest that never writes `\n` would either overrun the
/// buffer or force EL2 to drop bytes silently. 512 is comfortably over a kernel `printk` line
/// (~150 bytes at the widths this guest prints) and costs [`NUM_GUESTS`] × 512 bytes of `.bss`.
const LINE_CAP: usize = 512;

/// The serial line as shared by the real-Linux guests: one partial line per guest, plus the count of
/// whole lines each has had emitted.
///
/// The line count is a **witness**, not bookkeeping: it is EL2's own tally of how much console each
/// guest produced, and a guest that never ran has zero — see [`crate::linux`]'s per-guest report.
pub(crate) struct GuestConsole {
    /// Bytes of the current, unterminated line, per guest.
    line: [[u8; LINE_CAP]; NUM_GUESTS],
    /// How many of `line` are live, per guest.
    len: [usize; NUM_GUESTS],
    /// Whole lines emitted, per guest.
    lines: [u64; NUM_GUESTS],
}

impl GuestConsole {
    /// A console with nothing buffered and nothing emitted.
    pub(crate) const fn new() -> Self {
        Self {
            line: [[0; LINE_CAP]; NUM_GUESTS],
            len: [0; NUM_GUESTS],
            lines: [0; NUM_GUESTS],
        }
    }

    /// Accept one byte the guest in `slot` transmitted through its emulated `DR`, emitting the line
    /// if this byte terminates it.
    pub(crate) fn put(&mut self, slot: usize, byte: u8, uart: &mut Pl011) {
        if byte == b'\n' {
            self.emit(slot, uart);
            return;
        }
        if self.len[slot] == LINE_CAP {
            self.emit(slot, uart);
        }
        self.line[slot][self.len[slot]] = byte;
        self.len[slot] += 1;
    }

    /// Emit whatever `slot` has buffered but not terminated.
    ///
    /// Called when a guest powers off: its last line is often the one that says so, and a witness
    /// that swallowed it would be reporting less than the boot produced.
    pub(crate) fn flush(&mut self, slot: usize, uart: &mut Pl011) {
        if self.len[slot] != 0 {
            self.emit(slot, uart);
        }
    }

    /// Whole lines EL2 has emitted on `slot`'s behalf.
    pub(crate) fn lines(&self, slot: usize) -> u64 {
        self.lines[slot]
    }

    /// Put the buffered line on the wire under its guest's tag, and reset the buffer.
    fn emit(&mut self, slot: usize, uart: &mut Pl011) {
        let mut n = self.len[slot];
        // A tty with `ONLCR` writes `\r` immediately before every `\n`; keeping it would put a bare
        // carriage return in the middle of the line we are about to terminate ourselves.
        if n > 0 && self.line[slot][n - 1] == b'\r' {
            n -= 1;
        }
        let _ = write!(uart, "[dom {}] ", slot_dom(slot));
        for &byte in &self.line[slot][..n] {
            uart.put(byte);
        }
        // Written as the two bytes rather than through `write!`, because `Pl011`'s `fmt::Write` does
        // its own `\n` → `\r\n` translation and the guest's bytes above deliberately bypass it.
        uart.put(b'\r');
        uart.put(b'\n');
        self.len[slot] = 0;
        self.lines[slot] += 1;
    }
}
