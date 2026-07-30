// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The **emulated** GICv3 distributor + redistributor (③-b1, feature `real-linux`)
//!
//! ③-a1 took the guest's console. ③-a2 took its interrupt *delivery*. This takes the **interrupt
//! controller itself** — the last real device the real-Linux guest was still driving.
//!
//! ## Why it had to fall, and why it is the gate to ③-b
//!
//! ③-a2 left the GICD/GICR **pass-through**: the guest programmed the *real* distributor while EL2
//! injected through list registers. That works for one guest and cannot work for two, for exactly the
//! reason two guests cannot share one UART — a distributor is not a shareable resource. Worse than
//! "not shareable": a guest that reaches the real `GICD_ISENABLER` can enable, route and prioritise
//! **interrupts belonging to someone else**, which is a control channel, not merely a resource
//! conflict. So ③-b's second guest is blocked on this, and the shape is ③-a1's exactly: shrink the
//! window until the device falls out, then model its registers in EL2.
//!
//! **After this rung the real-Linux guest has NO Stage-2 device pass-through window at all** —
//! `stage2::windows().device_len == 0`, asserted at compile time below. Every device it touches is
//! EL2 state. That is the property ③-b needs, and it is now structural rather than argued.
//!
//! ## The register set is MEASURED, not taken from the spec
//!
//! A GICv3 distributor is a large surface, and implementing all of it would be a month of work
//! justified by nothing. So it was probed: the window was dropped and every guest access
//! traced *while passing through to real hardware*, so the boot completed and the trace covered it
//! end to end. **The whole boot touches the GIC 410 times**, across a small and regular set:
//!
//! | frame | registers the kernel actually uses |
//! |---|---|
//! | GICD | `CTLR` `TYPER` `IIDR` `TYPER2` `IGROUPR` `ISENABLER` `ICENABLER` `ICACTIVER` `IPRIORITYR` `ICFGR` `IROUTER` `PIDR2` |
//! | GICR (RD frame) | `CTLR` `TYPER` `WAKER` `PIDR2` |
//! | GICR (SGI frame) | `IGROUPR0` `ISENABLER0` `ICENABLER0` `ICACTIVER0` `IPRIORITYR` `ICFGR1` |
//!
//! **The probe's sharpest finding: the kernel's FIRST access is `GICD_PIDR2` (offset `0xffe8`)**, and
//! it reads bits [7:4] to identify the architecture. A RAZ/WI model returns 0 there, the kernel prints
//! *"no distributor detected, giving up"*, and **every later register is never touched** — so a
//! naive read-as-zero probe enumerates exactly one register and tells you nothing. That is why the
//! trace passes through to hardware instead of faking values.
//!
//! Registers outside the measured set are handled by the same rule ③-a1 used for undecodable PL011
//! accesses: they are **reported and parked**, never quietly zeroed. A guest that starts using a
//! register this model does not have is a guest whose expectations we are silently violating.
//!
//! ## What the model is FOR — mediation, not just answering
//!
//! Recording the guest's writes is the easy half. The half with the isolation content is that
//! [`crate::linux::handle_linux_irq`] now **consults this state before injecting**: a physical
//! interrupt is forwarded only if the guest has enabled that INTID in its own emulated distributor.
//! Before ③-b1 EL2 forwarded INTID 27 unconditionally, which was fine with one guest and is exactly
//! the decision that has to become per-guest for two.
//!
//! ## Declared residue — read before extending
//!
//! * **Pending/active state is write-accepted and reads as zero.** The trace shows the kernel never
//!   reads `ISPENDR`/`ISACTIVER` on this path, so modelling them would be untested code on a live
//!   path (design-lesson #71's shape). A guest that polls them gets zeros, which is wrong; it is
//!   declared here rather than half-built.
//! * **One redistributor, `Last` set.** Single-vCPU guest. A second vCPU needs a second frame and the
//!   affinity routing that `IROUTER` currently records and does not act on.
//! * **`IROUTER` is recorded, not honoured** — with one vCPU every SPI can only land in one place.
//!
//! ## Unsafe
//!
//! **None.** This module is a pure register file over EL2-owned memory: it touches no MMIO, no system
//! register, and no hardware. The one place the emulation meets the machine is EL2's own enable of a
//! *physical* interrupt it intends to forward, which lives in [`crate::gic`] where the rest of the
//! `unsafe` MMIO already is.

use crate::gic::{GICD_BASE, GICD_LEN, GICR_END, GICR_RD_BASE};

/// The guest's INTID space: 288 = `(ITLinesNumber + 1) * 32` with `ITLinesNumber = 8`, i.e. SGIs and
/// PPIs 0..31 plus SPIs 32..287.
///
/// **This is OUR choice, not a copy of the hardware's** — the distributor the guest sees is EL2
/// state, so its size is declared here and reported through [`GICD_TYPER`]. It is set to match the
/// `virt` machine's SPI count so the DTB's interrupt numbers (the PL011's SPI 1 ⇒ INTID 33, the
/// timer's PPI 11 ⇒ INTID 27) land in range with `guest.dts` unchanged, which is the same
/// "unmodified guest description" property ③-a1 preserved.
const NUM_INTIDS: usize = 288;

/// `NUM_INTIDS` rounded into 32-bit register words — the width of every `*ENABLER`/`*GROUPR` bank.
const WORDS: usize = NUM_INTIDS / 32;

/// The first SPI. INTIDs below this are SGIs (0..15) and PPIs (16..31), which live in the
/// redistributor's SGI frame rather than the distributor.
const FIRST_SPI: usize = 32;

/// The redistributor-banked INTIDs must fill whole words of BOTH bank shapes, or `dist_word_index`
/// would exclude a fraction of a word — leaving part of INTIDs 0..31 reachable from the distributor.
const _: () = assert!(
    FIRST_SPI.is_multiple_of(32) && FIRST_SPI.is_multiple_of(16),
    "the redistributor-banked INTIDs must fill whole words of every distributor bank shape"
);

const _: () = assert!(
    NUM_INTIDS.is_multiple_of(32),
    "the INTID space must fill whole registers"
);
const _: () = assert!(
    (crate::gic::VTIMER_INTID as usize) < NUM_INTIDS,
    "the forwarded timer INTID must exist in the emulated distributor"
);

/// **The distributor's register banks must not overlap.** Each `*ENABLER`/`*PENDR`/`*ACTIVER`/
/// `IGROUPR` bank is `4 * WORDS` bytes from its base, and the bases are 0x80 apart — so a bank
/// overruns its neighbour once `WORDS > 32`, i.e. `NUM_INTIDS > 1024`. The GICv3 maximum SPI is 1020
/// so the architecture already forbids it, but nothing in THIS file said so, and a bank silently
/// overlapping its neighbour is a decode that writes the wrong register: `word_index` would map an
/// offset into two different banks depending on which `if` ran first.
///
/// `IPRIORITYR` is byte-per-INTID rather than word-per-32, so it is checked against `ICFGR` too.
const _: () = assert!(
    4 * WORDS as u64 <= GICD_ICENABLER - GICD_ISENABLER
        && GICD_IPRIORITYR + NUM_INTIDS as u64 <= GICD_ICFGR,
    "the distributor's register banks overlap — a decode would write the wrong register"
);

/// **The ③-b1 headline, as a compile-time fact.** The real-Linux guest gets NO Stage-2 device
/// pass-through window: every device it touches — the PL011 (③-a1) and now the GIC — is emulated in
/// EL2. A non-zero window means some guest MMIO reaches real hardware again.
///
/// This **subsumes** [`crate::vpl011`]'s narrower assertion (that the window must not cover the
/// PL011); that one is kept because it records ③-a1's specific failure story, which this does not.
const _: () = assert!(
    crate::stage2::windows().device_len == 0,
    "the real-Linux guest must have no Stage-2 device pass-through window — every device it touches \
     is emulated in EL2 (vgic, vpl011)"
);

// ─── GICD register offsets (GICv3 Architecture Specification) ────────────────────────────────────
const GICD_CTLR: u64 = 0x0000;
const GICD_TYPER: u64 = 0x0004;
const GICD_IIDR: u64 = 0x0008;
const GICD_TYPER2: u64 = 0x000c;
const GICD_IGROUPR: u64 = 0x0080;
const GICD_ISENABLER: u64 = 0x0100;
const GICD_ICENABLER: u64 = 0x0180;
const GICD_ISPENDR: u64 = 0x0200;
const GICD_ICPENDR: u64 = 0x0280;
const GICD_ISACTIVER: u64 = 0x0300;
const GICD_ICACTIVER: u64 = 0x0380;
const GICD_IPRIORITYR: u64 = 0x0400;
const GICD_ICFGR: u64 = 0x0c00;
const GICD_IROUTER: u64 = 0x6000;
const GICD_PIDR2: u64 = 0xffe8;

// ─── GICR frame offsets. The redistributor is two 64 KiB frames: RD then SGI. ────────────────────
/// Size of one redistributor frame; the SGI frame starts one frame in.
const GICR_FRAME: u64 = 0x1_0000;
const GICR_CTLR: u64 = 0x0000;
const GICR_IIDR: u64 = 0x0004;
const GICR_TYPER: u64 = 0x0008;
const GICR_WAKER: u64 = 0x0014;
const GICR_PIDR2: u64 = 0xffe8;
const GICR_IGROUPR0: u64 = 0x0080;
const GICR_ISENABLER0: u64 = 0x0100;
const GICR_ICENABLER0: u64 = 0x0180;
const GICR_ISPENDR0: u64 = 0x0200;
const GICR_ICPENDR0: u64 = 0x0280;
const GICR_ISACTIVER0: u64 = 0x0300;
const GICR_ICACTIVER0: u64 = 0x0380;
const GICR_IPRIORITYR: u64 = 0x0400;
const GICR_ICFGR0: u64 = 0x0c00;
const GICR_ICFGR1: u64 = 0x0c04;

// ─── Values this distributor reports for itself ──────────────────────────────────────────────────

/// `GICD_CTLR.ARE_NS` (bit 4). Affinity routing is **not optional** here: it is what makes `IROUTER`
/// rather than the GICv2 `ITARGETSR` the routing register, and the model implements only the former.
const CTLR_ARE_NS: u32 = 1 << 4;
/// `GICD_CTLR` bits the guest may set — Group 0 / Group 1NS enables. `ARE_NS` is forced on and `RWP`
/// (bit 31, register-write-pending) is forced off: every write here completes before the trap
/// returns, so there is never anything pending to report.
const CTLR_WRITABLE: u32 = 0b11;

/// `GICD_TYPER`: `ITLinesNumber` in bits [4:0] such that `(N+1) * 32 == NUM_INTIDS`; `IDbits`
/// (bits [23:19]) = 9 ⇒ 10-bit INTIDs. No LPIs, no security extensions, no message-based SPIs.
const GICD_TYPER_VALUE: u32 = ((NUM_INTIDS / 32 - 1) as u32) | (9 << 19);

/// `GICD_IIDR` / `GICR_IIDR` — **deliberately Baleen's own, not QEMU's `0x43b`.** The guest is not
/// talking to the machine's distributor any more, and the identification register is the one place
/// the architecture provides to say so. A model that echoed the hardware's ID would be claiming to be
/// the hardware.
const BALEEN_IIDR: u32 = 0x0000_5ba1;

/// `*_PIDR2` — bits [7:4] are the GIC architecture revision, and **this is the register the kernel
/// reads first**; a wrong value here ends GIC probing before any other register is touched (measured,
/// see the module docs).
const PIDR2_GICV3: u32 = 3 << 4;

/// `GICR_TYPER`: `Last` (bit 4) — this is the only redistributor — with processor number 0 and
/// affinity 0. No LPI support advertised, which is why nothing in the model handles the LPI
/// configuration/pending tables.
const GICR_TYPER_VALUE: u64 = 1 << 4;

/// `GICR_WAKER.ProcessorSleep` (bit 1) — written by the guest to wake its redistributor.
const WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
/// `GICR_WAKER.ChildrenAsleep` (bit 2) — read-only, and the bit the guest polls. It mirrors
/// `ProcessorSleep`: the guest clears sleep, then spins until this clears. Modelling it as a mirror
/// makes that handshake terminate in one iteration, which is what the trace shows the hardware doing.
const WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

/// A guest MMIO access this model does not implement — reported by the caller with the syndrome, not
/// guessed at.
pub(crate) struct Unhandled {
    /// Which frame the access landed in, for the diagnostic.
    pub frame: &'static str,
    /// Offset within that frame.
    pub offset: u64,
}

/// The emulated GICv3 distributor + redistributor: one guest's interrupt-controller state, held in
/// EL2 memory where the guest cannot reach it.
pub(crate) struct VirtGic {
    /// `GICD_CTLR`, minus the bits this model forces ([`CTLR_ARE_NS`] on, `RWP` off).
    ctlr: u32,
    /// `GICR_WAKER.ProcessorSleep`. Starts asleep, as a redistributor does out of reset.
    asleep: bool,
    /// Interrupt-enable bits, one per INTID. **The load-bearing state**: `handle_linux_irq` consults
    /// it before forwarding a physical interrupt.
    enabled: [u32; WORDS],
    /// Group assignment (1 = Group 1, which is all this port delivers).
    group: [u32; WORDS],
    /// Per-INTID priority.
    priority: [u8; NUM_INTIDS],
    /// Per-INTID configuration, 2 bits each: edge/level.
    icfgr: [u32; NUM_INTIDS / 16],
    /// Per-SPI affinity routing. Recorded, not acted on — see the module docs' residue list.
    irouter: [u64; NUM_INTIDS - FIRST_SPI],
    /// How many register accesses the guest has made — the witness counter.
    traps: u64,
    /// How many distinct INTIDs the guest has ever enabled — the witness's discriminating half.
    enables: u64,
}

impl VirtGic {
    /// A distributor out of reset: everything disabled, redistributor asleep.
    pub(crate) const fn new() -> Self {
        Self {
            ctlr: 0,
            asleep: true,
            enabled: [0; WORDS],
            group: [0; WORDS],
            priority: [0; NUM_INTIDS],
            icfgr: [0; NUM_INTIDS / 16],
            irouter: [0; NUM_INTIDS - FIRST_SPI],
            traps: 0,
            enables: 0,
        }
    }

    /// **Is `intid` enabled in the guest's own distributor?** The mediation seam: EL2 forwards a
    /// physical interrupt only when the guest has asked for it, rather than whenever one arrives.
    pub(crate) fn is_enabled(&self, intid: u32) -> bool {
        let i = intid as usize;
        i < NUM_INTIDS && self.enabled[i / 32] & (1 << (i % 32)) != 0
    }

    /// `(register traps, distinct INTIDs ever enabled)` — the ③-b1 witness.
    pub(crate) fn witness(&self) -> (u64, u64) {
        (self.traps, self.enables)
    }

    /// Service a guest **read** of the emulated GIC at `ipa`, `size` bytes wide.
    pub(crate) fn mmio_read(&mut self, ipa: u64, size: u64) -> Result<u64, Unhandled> {
        self.traps += 1;
        let Some((frame, off)) = frame_of(ipa) else {
            return Err(Unhandled {
                frame: "outside every emulated GIC frame",
                offset: ipa,
            });
        };
        match frame {
            Frame::Dist => self.dist_read(off, size),
            Frame::Redist => self.redist_read(off),
            Frame::Sgi => self.sgi_read(off),
        }
        .ok_or(Unhandled {
            frame: frame.name(),
            offset: off,
        })
    }

    /// Service a guest **write** of the emulated GIC at `ipa`, `size` bytes wide.
    pub(crate) fn mmio_write(&mut self, ipa: u64, size: u64, value: u64) -> Result<(), Unhandled> {
        self.traps += 1;
        let Some((frame, off)) = frame_of(ipa) else {
            return Err(Unhandled {
                frame: "outside every emulated GIC frame",
                offset: ipa,
            });
        };
        let ok = match frame {
            Frame::Dist => self.dist_write(off, size, value),
            Frame::Redist => self.redist_write(off, value as u32),
            Frame::Sgi => self.sgi_write(off, value as u32),
        };
        if ok {
            Ok(())
        } else {
            Err(Unhandled {
                frame: frame.name(),
                offset: off,
            })
        }
    }

    // ─── the distributor frame ───────────────────────────────────────────────────────────────────

    fn dist_read(&self, off: u64, size: u64) -> Option<u64> {
        // `IROUTER` is the only 64-bit-wide register in the frame, and the trace confirms the kernel
        // writes it 64 bits at a time.
        if let Some(i) = irouter_index(off) {
            return Some(self.irouter[i]);
        }
        let v = match off {
            GICD_CTLR => self.ctlr | CTLR_ARE_NS,
            GICD_TYPER => GICD_TYPER_VALUE,
            GICD_IIDR => BALEEN_IIDR,
            GICD_TYPER2 => 0,
            GICD_PIDR2 => PIDR2_GICV3,
            _ => return self.dist_bank_read(off, size),
        };
        Some(v as u64)
    }

    /// The banked per-INTID registers of the distributor, which all index by INTID off a base.
    fn dist_bank_read(&self, off: u64, _size: u64) -> Option<u64> {
        if let Some(w) = dist_word_index(off, GICD_IGROUPR, WORDS, 32) {
            return Some(self.group[w] as u64);
        }
        // Set and clear registers read back the same underlying bank.
        if let Some(w) = dist_word_index(off, GICD_ISENABLER, WORDS, 32) {
            return Some(self.enabled[w] as u64);
        }
        if let Some(w) = dist_word_index(off, GICD_ICENABLER, WORDS, 32) {
            return Some(self.enabled[w] as u64);
        }
        // Pending/active: declared residue — accepted, always read as zero. See the module docs.
        if dist_word_index(off, GICD_ISPENDR, WORDS, 32).is_some()
            || dist_word_index(off, GICD_ICPENDR, WORDS, 32).is_some()
            || dist_word_index(off, GICD_ISACTIVER, WORDS, 32).is_some()
            || dist_word_index(off, GICD_ICACTIVER, WORDS, 32).is_some()
        {
            return Some(0);
        }
        if let Some(w) = dist_word_index(off, GICD_ICFGR, NUM_INTIDS / 16, 16) {
            return Some(self.icfgr[w] as u64);
        }
        if (GICD_IPRIORITYR + FIRST_SPI as u64..GICD_IPRIORITYR + NUM_INTIDS as u64).contains(&off)
        {
            // Priority is byte-addressed but usually accessed a word at a time; return the word the
            // offset falls in, assembled from the bytes. Starts at the first SPI: the distributor's
            // copies of INTIDs 0..31 are RES0 (see `dist_word_index`).
            let base = (off - GICD_IPRIORITYR) as usize & !3;
            let mut v = 0u64;
            for k in 0..4 {
                v |= (self.priority[base + k] as u64) << (8 * k);
            }
            return Some(v);
        }
        None
    }

    fn dist_write(&mut self, off: u64, _size: u64, value: u64) -> bool {
        if let Some(i) = irouter_index(off) {
            self.irouter[i] = value;
            return true;
        }
        let v = value as u32;
        match off {
            GICD_CTLR => {
                self.ctlr = v & CTLR_WRITABLE;
                return true;
            }
            // The identification registers are read-only; a write to them is a guest bug, not ours.
            GICD_TYPER | GICD_IIDR | GICD_TYPER2 | GICD_PIDR2 => return true,
            _ => {}
        }
        if let Some(w) = dist_word_index(off, GICD_IGROUPR, WORDS, 32) {
            self.group[w] = v;
            return true;
        }
        if let Some(w) = dist_word_index(off, GICD_ISENABLER, WORDS, 32) {
            self.set_enabled(w, v);
            return true;
        }
        if let Some(w) = dist_word_index(off, GICD_ICENABLER, WORDS, 32) {
            self.enabled[w] &= !v;
            return true;
        }
        if dist_word_index(off, GICD_ISPENDR, WORDS, 32).is_some()
            || dist_word_index(off, GICD_ICPENDR, WORDS, 32).is_some()
            || dist_word_index(off, GICD_ISACTIVER, WORDS, 32).is_some()
            || dist_word_index(off, GICD_ICACTIVER, WORDS, 32).is_some()
        {
            return true; // declared residue
        }
        if let Some(w) = dist_word_index(off, GICD_ICFGR, NUM_INTIDS / 16, 16) {
            self.icfgr[w] = v;
            return true;
        }
        if (GICD_IPRIORITYR + FIRST_SPI as u64..GICD_IPRIORITYR + NUM_INTIDS as u64).contains(&off)
        {
            let base = (off - GICD_IPRIORITYR) as usize & !3;
            for k in 0..4 {
                self.priority[base + k] = (value >> (8 * k)) as u8;
            }
            return true;
        }
        false
    }

    // ─── the redistributor's RD frame ────────────────────────────────────────────────────────────

    fn redist_read(&self, off: u64) -> Option<u64> {
        let v = match off {
            GICR_CTLR => 0u64,
            GICR_IIDR => BALEEN_IIDR as u64,
            GICR_TYPER => GICR_TYPER_VALUE,
            GICR_WAKER => {
                if self.asleep {
                    (WAKER_PROCESSOR_SLEEP | WAKER_CHILDREN_ASLEEP) as u64
                } else {
                    0
                }
            }
            GICR_PIDR2 => PIDR2_GICV3 as u64,
            _ => return None,
        };
        Some(v)
    }

    fn redist_write(&mut self, off: u64, value: u32) -> bool {
        match off {
            // `ChildrenAsleep` is read-only; only `ProcessorSleep` is taken from the write, and the
            // read side mirrors it so the guest's wake handshake terminates.
            GICR_WAKER => {
                self.asleep = value & WAKER_PROCESSOR_SLEEP != 0;
                true
            }
            GICR_CTLR | GICR_IIDR | GICR_TYPER | GICR_PIDR2 => true,
            _ => false,
        }
    }

    // ─── the redistributor's SGI frame: INTIDs 0..31, this vCPU's SGIs and PPIs ──────────────────

    fn sgi_read(&self, off: u64) -> Option<u64> {
        let v = match off {
            GICR_IGROUPR0 => self.group[0],
            GICR_ISENABLER0 | GICR_ICENABLER0 => self.enabled[0],
            // Declared residue, as in the distributor.
            GICR_ISPENDR0 | GICR_ICPENDR0 | GICR_ISACTIVER0 | GICR_ICACTIVER0 => 0,
            GICR_ICFGR0 => self.icfgr[0],
            GICR_ICFGR1 => self.icfgr[1],
            _ => {
                if (GICR_IPRIORITYR..GICR_IPRIORITYR + FIRST_SPI as u64).contains(&off) {
                    let base = (off - GICR_IPRIORITYR) as usize & !3;
                    let mut v = 0u32;
                    for k in 0..4 {
                        v |= (self.priority[base + k] as u32) << (8 * k);
                    }
                    v
                } else {
                    return None;
                }
            }
        };
        Some(v as u64)
    }

    fn sgi_write(&mut self, off: u64, value: u32) -> bool {
        match off {
            GICR_IGROUPR0 => self.group[0] = value,
            GICR_ISENABLER0 => self.set_enabled(0, value),
            GICR_ICENABLER0 => self.enabled[0] &= !value,
            GICR_ISPENDR0 | GICR_ICPENDR0 | GICR_ISACTIVER0 | GICR_ICACTIVER0 => {}
            GICR_ICFGR0 => self.icfgr[0] = value,
            GICR_ICFGR1 => self.icfgr[1] = value,
            _ => {
                if (GICR_IPRIORITYR..GICR_IPRIORITYR + FIRST_SPI as u64).contains(&off) {
                    let base = (off - GICR_IPRIORITYR) as usize & !3;
                    for k in 0..4 {
                        self.priority[base + k] = (value >> (8 * k)) as u8;
                    }
                } else {
                    return false;
                }
            }
        }
        true
    }

    /// Set enable bits in bank `w`, counting the INTIDs that were **newly** enabled.
    ///
    /// The count is the witness's discriminating half: it is a statement about the guest having
    /// programmed THIS distributor, which a pass-through configuration could not produce because the
    /// writes would never have been seen.
    fn set_enabled(&mut self, w: usize, bits: u32) {
        let newly = bits & !self.enabled[w];
        self.enabled[w] |= bits;
        self.enables += newly.count_ones() as u64;
    }
}

/// Which of the three emulated frames an address lands in.
#[derive(Clone, Copy)]
enum Frame {
    Dist,
    Redist,
    Sgi,
}

impl Frame {
    fn name(self) -> &'static str {
        match self {
            Frame::Dist => "GICD",
            Frame::Redist => "GICR",
            Frame::Sgi => "GICR_SGI",
        }
    }
}

/// Split a guest IPA into `(frame, offset within frame)`, or `None` if it is in no frame at all.
///
/// The redistributor region `guest.dts` declares is much larger than the two frames a single-CPU
/// guest has (it is sized for the machine's maximum CPU count). Everything past the SGI frame is
/// therefore *in the window* but in no frame, and lands on the `Unhandled` path — reported, not
/// silently absorbed, because an access there means the guest believes in a redistributor that does
/// not exist.
fn frame_of(ipa: u64) -> Option<(Frame, u64)> {
    // **Total, not caller-guarded.** This used to subtract `GICD_BASE` unconditionally, which
    // UNDERFLOWS for any address below the distributor — wrapping in release to a huge offset that
    // happened to fall through to `Unhandled`. It failed closed by luck, and only because
    // [`in_window`] — a *separate* function the caller had to remember — kept such an address out.
    // A device model reached with a guest-derived address should not have preconditions its own
    // entry points do not enforce.
    if !in_window(ipa) {
        return None;
    }
    if ipa < GICR_RD_BASE {
        return Some((Frame::Dist, ipa - GICD_BASE));
    }
    let off = ipa - GICR_RD_BASE;
    Some(if off < GICR_FRAME {
        (Frame::Redist, off)
    } else {
        (Frame::Sgi, off - GICR_FRAME)
    })
}

/// If `off` names a `GICD_IROUTER<n>` entry, its index into [`VirtGic::irouter`].
///
/// **`IROUTER` is indexed by INTID, not by position within the bank**, so entry `n` sits at
/// `0x6000 + 8n` and the first *valid* entry is the first SPI — `0x6100`, not `0x6000`. Getting that
/// wrong costs the top 32 SPIs, which is precisely how it announced itself: the kernel writes the
/// whole routing table on boot, ran off the end at `0x6800`, and parked. (The measured trace shows
/// exactly `0x6100..=0x68f8`, i.e. INTIDs 32..=287.)
fn irouter_index(off: u64) -> Option<usize> {
    let first = GICD_IROUTER + 8 * FIRST_SPI as u64;
    let end = GICD_IROUTER + 8 * NUM_INTIDS as u64;
    if off < first || off >= end || !off.is_multiple_of(8) {
        return None;
    }
    Some(((off - first) / 8) as usize)
}

/// If `off` names a word of a DISTRIBUTOR bank, its index — **excluding word 0**.
///
/// **The distributor does not own INTIDs 0..31.** With `GICD_CTLR.ARE_NS` set (which this model
/// forces), SGIs and PPIs are banked *per redistributor*, and the distributor's copies of them are
/// RES0. Before this guard `GICD_ISENABLER0` and `GICR_ISENABLER0` both reached `enabled[0]`, so a
/// write the architecture reserves could change the guest's PPI enables — and, worse for the proofs,
/// it meant the two frames deliberately SHARED state, which makes "the decode is a partition" false
/// as a theorem rather than merely hard to state.
///
/// Behaviour-preserving for the shipped guest, and that is measured, not assumed: the ③-b1 register
/// trace shows the kernel's `GICD_ISENABLER`/`IGROUPR`/`ICFGR` writes starting at word 1 and its
/// `GICD_IPRIORITYR` writes at `0x420` (INTID 32) — it never touches the distributor's copies of
/// 0..31, because Linux knows they are reserved too.
fn dist_word_index(off: u64, base: u64, count: usize, intids_per_word: usize) -> Option<usize> {
    // How many whole words the redistributor-banked INTIDs occupy. **`intids_per_word` is not always
    // 32**: the `*ENABLER`/`*PENDR`/`*ACTIVER`/`IGROUPR` banks are one bit per INTID (32 per word),
    // but `ICFGR` is TWO bits (16 per word) — so INTIDs 0..31 span its words 0 AND 1. Excluding only
    // word 0, as the first cut of this guard did, left `GICD_ICFGR1` still aliasing `GICR_ICFGR1`.
    let banked_words = FIRST_SPI / intids_per_word;
    match word_index(off, base, count) {
        Some(w) if w >= banked_words => Some(w),
        _ => None,
    }
}

/// If `off` names a word of a `count`-word register bank based at `base`, its index.
fn word_index(off: u64, base: u64, count: usize) -> Option<usize> {
    if off < base || off >= base + 4 * count as u64 || !off.is_multiple_of(4) {
        return None;
    }
    Some(((off - base) / 4) as usize)
}

/// `true` iff `ipa` falls in the emulated GIC's windows, so the real-Linux data-abort handler routes
/// it here rather than reporting an unexpected fault.
pub(crate) fn in_window(ipa: u64) -> bool {
    (GICD_BASE..GICD_BASE + GICD_LEN).contains(&ipa) || (GICR_RD_BASE..GICR_END).contains(&ipa)
}
