// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Deploying the emulated PL011 on *this* machine (③-a1, feature `real-linux`)
//!
//! Until ③-a1 the real-Linux guest *owned* the machine's PL011: the pass-through device window ran
//! `0x0800_0000 .. 0x0a00_0000` (32 MiB), so `0x0900_0000` was mapped into the guest's Stage-2 and
//! every character the kernel printed was a store the guest made **directly to the hardware**. That
//! is fine for one guest and impossible for two: a UART is not a shareable resource, and
//! `linux.rs`'s own module doc named the pass-through model as the thing a second guest would break.
//!
//! So the window shrank — first to 16 MiB when the PL011 fell out of it (③-a1), then to **zero**
//! when the GIC did too (③-b1) — and a guest access to `0x0900_0000` became a Stage-2 translation
//! fault to EL2.
//!
//! ## What is here, after ⑯ moved the model out
//!
//! The **register file itself now lives in [`hv_vdev::pl011`]**, under the workspace's
//! `unsafe_code = "forbid"` fence where `hv-verify` can reach it — see that crate's docs for why.
//! What stays here is everything that is a claim about *this board* rather than about a PL011:
//!
//! - **The address and window** ([`VPL011_BASE`], [`VPL011_SIZE`], [`in_window`]) — the model is
//!   offset-based and does not know where it is deployed.
//! - **The two `const assert!`s** below, which bind the model to the machine.
//! - **The witness** ([`DeployedPl011`]) — trap and byte counts, and the marker matcher, wrapped
//!   around the model rather than living inside it. ⑯'s crate docs explain the reasoning: a counter
//!   inside the device made `mmio_read` take `&mut self`, which made "a failed access changes
//!   nothing" unstateable for the sibling GIC model and forced every property to carry an exception
//!   clause for fields that are not device state at all.
//! - **The hardware poke.** [`hv_vdev::pl011::VirtPl011::mmio_write`] *reports* a transmitted byte;
//!   `linux.rs` is what puts it on the real UART. That is the one place the emulated device meets
//!   the real one, and keeping it at the call site is what leaves the model free of `unsafe`.
//!
//! ## Unsafe
//!
//! **None in this module.** The one `unsafe` in the path is the existing volatile MMIO in
//! [`crate::pl011`], reached because the model hands the caller a byte to transmit rather than
//! touching hardware itself.

use hv_vdev::pl011::{NeedleMatcher, VirtPl011};

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
//
// **They stay in `hv-metal` on purpose.** Each mentions a constant of *this* machine — the real
// UART's address, the emitted Stage-2 window — which the model under the fence has no business
// knowing. A platform-neutral device model with a board's addresses compiled into it is not
// platform-neutral; it is a board's device model with the dependency hidden.

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

/// The userspace marker the emulator watches for in the guest's own transmit stream.
///
/// **This is what makes the witness discriminating** (design-lesson #24f, and #71 read from the
/// failure side). Every other marker in the real-Linux gate — `Linux version`, `Machine model`,
/// `BALEEN-STEP0-OK` — appears on the serial console whether the PL011 is emulated or passed
/// through, so none of them can tell the two apart. This one can: the bytes are counted *inside*
/// [`DeployedPl011::mmio_write`], so the claim "the guest's console goes through EL2" is made by the
/// mechanism that would have to be running for it to be true.
const NEEDLE: &[u8] = b"BALEEN-STEP0-OK";

/// The emulated PL011 **as deployed**: the proven register file, plus the evidence that it ran.
///
/// The split is the point. [`VirtPl011`] is what a guest driver can observe and is provable in
/// isolation; the counters here are what the boot gate reads and mean nothing to a driver. Keeping
/// them apart is what lets the model's theorems quantify over the whole of its state.
pub(crate) struct DeployedPl011 {
    /// The model, under the fence.
    dev: VirtPl011,
    /// Rolling match of [`NEEDLE`] over the guest's transmit stream.
    needle: NeedleMatcher,
    /// Register accesses trapped and serviced (reads and writes).
    traps: u64,
    /// Bytes the guest transmitted through `DR`, i.e. forwarded to the real UART.
    dr_writes: u64,
}

impl DeployedPl011 {
    /// The device at reset, with an unfired witness.
    pub(crate) const fn new() -> Self {
        Self {
            dev: VirtPl011::new(),
            needle: NeedleMatcher::new(NEEDLE),
            traps: 0,
            dr_writes: 0,
        }
    }

    /// Service a guest **read** at `offset` (relative to [`VPL011_BASE`]), `bytes` wide.
    pub(crate) fn mmio_read(&mut self, offset: u64, bytes: u64) -> u64 {
        self.traps += 1;
        self.dev.mmio_read(offset, bytes)
    }

    /// Service a guest **write** of `value` at `offset`. Returns `Some(byte)` iff the write was to
    /// `DR` — the caller then puts that byte on the real UART.
    #[must_use]
    pub(crate) fn mmio_write(&mut self, offset: u64, value: u64) -> Option<u8> {
        self.traps += 1;
        let out = self.dev.mmio_write(offset, value);
        if let Some(byte) = out {
            self.dr_writes += 1;
            self.needle.feed(byte);
        }
        out
    }

    /// The witness this device produces: the guest's console output reached the serial line
    /// **through EL2**, evidenced by userspace's own marker having passed through `DR` here.
    ///
    /// Returns `(ok, traps, dr_writes)`. `ok` is false — and the boot says so by name — if the
    /// emulator was never entered (the window is passed through again) or was entered but never
    /// carried the guest's userspace output (the transmit path is broken).
    pub(crate) fn witness(&self) -> (bool, u64, u64) {
        (
            self.needle.saw() && self.dr_writes > 0,
            self.traps,
            self.dr_writes,
        )
    }
}
