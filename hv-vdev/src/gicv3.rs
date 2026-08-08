// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The emulated GICv3 distributor + redistributor
//!
//! ③-a1 took the guest's console. ③-a2 took its interrupt *delivery*. ③-b1 took the **interrupt
//! controller itself** — the last real device the real-Linux guest was still driving — and this is
//! that model, moved under the fence by ⑯.
//!
//! ## Why it had to fall
//!
//! ③-a2 left the GICD/GICR **pass-through**: the guest programmed the *real* distributor while EL2
//! injected through list registers. That works for one guest and cannot work for two, for exactly
//! the reason two guests cannot share one UART — a distributor is not a shareable resource. Worse
//! than "not shareable": a guest that reaches the real `GICD_ISENABLER` can enable, route and
//! prioritise **interrupts belonging to someone else**, which is a control channel, not merely a
//! resource conflict.
//!
//! ## The register set is MEASURED, not taken from the spec
//!
//! A GICv3 distributor is a large surface, and implementing all of it would be a month of work
//! justified by nothing. So it was probed: the window was dropped and every guest access traced
//! *while passing through to real hardware*, so the boot completed and the trace covered it end to
//! end. **The whole boot touches the GIC 410 times**, across a small and regular set:
//!
//! | frame | registers the kernel actually uses |
//! |---|---|
//! | GICD | `CTLR` `TYPER` `IIDR` `TYPER2` `IGROUPR` `ISENABLER` `ICENABLER` `ICACTIVER` `IPRIORITYR` `ICFGR` `IROUTER` `PIDR2` |
//! | GICR (RD frame) | `CTLR` `TYPER` `WAKER` `PIDR2` |
//! | GICR (SGI frame) | `IGROUPR0` `ISENABLER0` `ICENABLER0` `ICACTIVER0` `IPRIORITYR` `ICFGR1` |
//!
//! **The probe's sharpest finding: the kernel's FIRST access is `GICD_PIDR2` (offset `0xffe8`)**,
//! and it reads bits `[7:4]` to identify the architecture. A RAZ/WI model returns 0 there, the kernel
//! prints *"no distributor detected, giving up"*, and **every later register is never touched** — so
//! a naive read-as-zero probe enumerates exactly one register and tells you nothing. That is why the
//! trace passes through to hardware instead of faking values.
//!
//! Registers outside the measured set are handled by the same rule ③-a1 used for undecodable PL011
//! accesses: they are **reported and parked**, never quietly zeroed. A guest that starts using a
//! register this model does not have is a guest whose expectations we are silently violating.
//!
//! ## What the model is FOR — mediation, not just answering
//!
//! Recording the guest's writes is the easy half. The half with the isolation content is that the
//! caller **consults this state before injecting**: a physical interrupt is forwarded only if the
//! guest has enabled that INTID in its own emulated distributor. Before ③-b1 EL2 forwarded INTID 27
//! unconditionally, which was fine with one guest and is exactly the decision that has to become
//! per-guest for two. [`VirtGic::is_enabled`] is that seam.
//!
//! ## The address map is a PARAMETER, and that is the point of being here
//!
//! In `hv-metal` this model imported four platform constants directly from the GIC driver. Under
//! the fence they become a [`GicLayout`], because the cheap alternative — re-declaring the board's
//! addresses inside this crate — is a *second derivation* of them, which is the defect ⑭ spent a
//! whole rung removing. The parameterization is not a cost of the move; it is one of its results.
//!
//! ## Declared residue — read before extending
//!
//! Three were declared here; **two are now closed** (⑱-2, ⑱-6) and the remaining one is **PINNED BY
//! KANI** (`hv-verify`'s `gic_declared_residues`), because a prose residue drifts: someone
//! half-implements pending state, the docs still say "reads as zero", and no boot can tell because
//! the shipped guest never looks. As a theorem it cannot drift.
//!
//! ★ The closed entries are kept, struck through, with what closed them — a residue list that
//! deleted its discharged items would read as if it had never been wrong, and the *shape* of how
//! each one closed is the transferable part.
//!
//! * **Pending/active state is write-accepted and reads as zero — FOR SPIs.** The trace shows the
//!   kernel never reads `ISPENDR`/`ISACTIVER` on this path, so modelling them would be untested code
//!   on a live path (design-lesson #71's shape). A guest that polls them gets zeros, which is wrong;
//!   it is declared here rather than half-built.
//!
//!   ⚠ **This used to say "reads as zero" flatly, and that was WRONG — the proof found it.** Word 0
//!   of those distributor banks is INTIDs 0..31, which are banked in the REDISTRIBUTOR and excluded
//!   from the distributor's decode (`ARE_NS` makes the distributor's copies RES0 — see the bank-
//!   overlap note below). So word 0 is **refused**, not zeroed. **And a refusal is no longer inert:**
//!   since the retire rung an unmodelled register stops the guest, so a guest reading `GICD_ISPENDR0`
//!   — architecturally a RES0 read that should return zero — is retired. The redistributor's own
//!   copies, where 0..31 legitimately live, do read zero.
//!
//!   **Recorded, not changed.** Making word 0 read zero would be architecturally right and would
//!   remove a guest-triggerable retirement; it also changes the guest's device surface, so it is a
//!   decision of its own rather than a detail of pinning a declaration.
//! * ~~**One redistributor, `Last` set.**~~ **CLOSED BY ⑱-2.** The model presents one redistributor
//!   **per vCPU** — [`VirtGic`] is generic over `VCPUS` — each with its own banked INTIDs 0..31, its
//!   own `GICR_WAKER` handshake, and a `GICR_TYPER` carrying its own affinity and processor number
//!   with `Last` on exactly the final one.
//!
//!   ⚠ **This entry used to end "`hv-metal` still deploys `VirtGic<1>`, so nothing that boots
//!   exercises the second redistributor — the evidence is the proofs". THAT IS NO LONGER TRUE, and
//!   it stopped being true two rungs before anyone corrected it.** `hv-metal`'s `vgic.rs` deploys
//!   `VirtGic<{ role::VCPUS_PER_GUEST }>`, and ⑱-3b-ii raised that constant to 2 — so the boot has
//!   been walking both frames since then, measured as **410 → 413 GICD/GICR register traps per
//!   dom**. ⑱-4b-ii makes it load-bearing rather than merely exercised: a secondary started by
//!   `PSCI CPU_ON` matches its own `MPIDR_EL1` against each `GICR_TYPER` affinity in
//!   `gic_populate_rdist`, and boots only if it finds ITS OWN frame. Corrected by ⑱-4b-ii; the
//!   proofs below remain the ∀-value evidence, but they are no longer the ONLY evidence.
//! * ~~**`IROUTER` is recorded, not honoured**~~ **CLOSED BY ⑱-6.** [`VirtGic::spi_route`] reads the
//!   routing the guest wrote and [`irouter::SpiRoute::targets`](crate::irouter::SpiRoute::targets)
//!   says which vCPU it names; `hv-metal` delivers there rather than to whichever vCPU is running.
//!
//!   ★ **The deferral expired on schedule, and that is why it was written with a condition
//!   attached.** This entry used to end: *"it needs a second vCPU per guest to matter, so
//!   implementing it now would add unexercised code to the guest's device surface"* — design-lesson
//!   #71 and III-2's "deferred for want of a consumer". `VCPUS_PER_GUEST` is 2 and both run, so the
//!   same rule that justified waiting now requires the opposite. A bare "later" could not have been
//!   discharged; a named condition could.
//!
//! ## ⑱-2 — what proves the multi-redistributor model, given that no boot can
//!
//! The metal deploys one vCPU, so **every property below is invisible to the boot gate** and the
//! proofs are the whole of the evidence. In `hv-verify`'s `device_models`:
//! `a_write_to_one_redistributor_changes_nothing_another_reads` ·
//! `enabling_an_intid_for_one_vcpu_does_not_enable_it_for_another` (**the isolation pair — read the
//! note on that second one, neither catches what the other does**) ·
//! `the_last_redistributor_is_the_only_one_that_says_so` · `the_typer_reports_the_vcpu_affinity` ·
//! `the_decode_is_a_partition_across_redistributors` ·
//! `an_address_past_the_last_redistributor_is_in_no_frame` ·
//! `a_layout_valid_for_two_has_room_for_two` · two totality harnesses at `VCPUS = 2` · and
//! `the_second_redistributor_is_reached_and_is_its_own` for non-vacuity. **Four kill probes were run
//! and are tabulated beside those harnesses.**

/// The guest's INTID space: 288 = `(ITLinesNumber + 1) * 32` with `ITLinesNumber = 8`, i.e. SGIs and
/// PPIs 0..31 plus SPIs 32..287.
///
/// **This is OUR choice, not a copy of the hardware's** — the distributor the guest sees is EL2
/// state, so its size is declared here and reported through `GICD_TYPER`. It is set to match the
/// `virt` machine's SPI count so the DTB's interrupt numbers (the PL011's SPI 1 ⇒ INTID 33, the
/// timer's PPI 11 ⇒ INTID 27) land in range with `guest.dts` unchanged, which is the same
/// "unmodified guest description" property ③-a1 preserved.
///
/// Public because the deployment asserts that its board's interrupts fit — see `hv-metal`'s
/// `VTIMER_INTID < NUM_INTIDS`, which is a claim about the machine and so stays there.
pub const NUM_INTIDS: usize = 288;

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
/// Size of one redistributor frame; the SGI frame starts one frame in. **Architectural**, not a
/// property of the board, which is why it is a constant here and not part of [`GicLayout`].
const GICR_FRAME: u64 = 0x1_0000;
/// How many frames a redistributor occupies — the RD frame and the SGI frame.
const GICR_FRAMES: u64 = 2;
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

/// `GICD_TYPER.No1N`, bit 25 — **1 = 1-of-N distribution is not supported.**
///
/// ⑱-6. This is a *declaration*, and it is what makes [`irouter`](crate::irouter)'s decode total
/// over everything a conforming guest can ask for: told 1-of-N is unavailable, a guest never sets
/// `GICD_IROUTER<n>.IRM`, so every routing value names exactly one PE. The alternative was for the
/// hypervisor to invent a policy for "any PE" that no guest asked for and no artifact could check.
/// See that module's docs for the full argument (design-lesson #202).
const GICD_TYPER_NO_1_OF_N: u32 = 1 << 25;

/// `GICD_TYPER`: `ITLinesNumber` in bits `[4:0]` such that `(N+1) * 32 == NUM_INTIDS`; `IDbits`
/// (bits `[23:19]`) = 9 ⇒ 10-bit INTIDs; `No1N` (bit 25). No LPIs, no security extensions, no
/// message-based SPIs.
const GICD_TYPER_VALUE: u32 = ((NUM_INTIDS / 32 - 1) as u32) | (9 << 19) | GICD_TYPER_NO_1_OF_N;

/// `GICD_IIDR` / `GICR_IIDR` — **deliberately Baleen's own, not QEMU's `0x43b`.** The guest is not
/// talking to the machine's distributor any more, and the identification register is the one place
/// the architecture provides to say so. A model that echoed the hardware's ID would be claiming to
/// be the hardware.
const BALEEN_IIDR: u32 = 0x0000_5ba1;

/// `*_PIDR2` — bits `[7:4]` are the GIC architecture revision, and **this is the register the kernel
/// reads first**; a wrong value here ends GIC probing before any other register is touched
/// (measured, see the module docs).
const PIDR2_GICV3: u32 = 3 << 4;

/// `GICR_TYPER.Last` (bit 4) — "this is the last redistributor in the region". **A guest walks the
/// redistributor region reading `GICR_TYPER` and stops at the frame that sets this**, which is why
/// exactly one must, and why it must be the last one ([`VirtGic::gicr_typer`]).
const GICR_TYPER_LAST: u64 = 1 << 4;

/// `GICR_TYPER.Processor_Number`, bits `[15:8]`.
const GICR_TYPER_PROC_SHIFT: u32 = 8;

/// `GICR_TYPER.Affinity_Value`, bits `[63:32]` — `Aff3:Aff2:Aff1:Aff0`, one byte each, so `Aff0`
/// lands at bit 32.
const GICR_TYPER_AFF_SHIFT: u32 = 32;

/// **The affinity a vCPU has, and the ONE place that answer is derived.**
///
/// Two artifacts must agree about which vCPU is which: this model, through `GICR_TYPER`'s affinity
/// field, and the `MPIDR_EL1` the guest reads — which on baleen is `VMPIDR_EL2`, written by
/// `hv-metal`'s `guest_mpidr` (⑱-1). **A guest matches the two against each other**: arm64 Linux's
/// `gic_populate_rdist` walks the redistributors looking for the frame whose affinity equals its own
/// MPIDR, and fails the CPU if none does. Two encodings of that mapping would agree until somebody
/// changed one, so `hv-metal` calls this rather than repeating it — design-lesson #74.
///
/// `Aff0 = vcpu`, every other affinity level zero: one cluster, N cores.
#[must_use]
pub const fn vcpu_affinity(vcpu: usize) -> u64 {
    vcpu as u64
}

/// `GICR_WAKER.ProcessorSleep` (bit 1) — written by the guest to wake its redistributor.
const WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
/// `GICR_WAKER.ChildrenAsleep` (bit 2) — read-only, and the bit the guest polls. It mirrors
/// `ProcessorSleep`: the guest clears sleep, then spins until this clears. Modelling it as a mirror
/// makes that handshake terminate in one iteration, which is what the trace shows the hardware
/// doing.
const WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

/// Where the emulated distributor and redistributor sit in the guest's address space.
///
/// **A parameter, not a constant, and the crate docs say why.** The board's addresses live in
/// `hv-metal`; this type is how they reach the model without being duplicated into it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GicLayout {
    gicd_base: u64,
    gicd_len: u64,
    gicr_rd_base: u64,
    gicr_end: u64,
}

/// Which emulated frame an address lands in — and, for the redistributor frames, **whose**.
///
/// ⑱-2 gave the two redistributor variants a vCPU index. There is one redistributor per vCPU and
/// each owns its own copy of INTIDs 0..31, so "which frame" is not a complete answer to where a
/// guest access goes; without the index the model would decode N redistributors onto one bank, which
/// is precisely the aliasing `the_decode_is_a_partition` exists to forbid.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GicFrame {
    /// The distributor — one per guest, holding the SPIs.
    Dist,
    /// vCPU `n`'s redistributor RD frame.
    Redist(usize),
    /// vCPU `n`'s redistributor SGI frame — INTIDs 0..31, that vCPU's own SGIs and PPIs.
    Sgi(usize),
}

impl GicFrame {
    /// The frame's architectural name, for a diagnostic. **Not the vCPU** — the index is reported
    /// separately by callers that have one, so this stays a `&'static str` and needs no allocation.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            GicFrame::Dist => "GICD",
            GicFrame::Redist(_) => "GICR",
            GicFrame::Sgi(_) => "GICR_SGI",
        }
    }

    /// The vCPU whose redistributor this frame belongs to, or `None` for the distributor.
    #[must_use]
    pub const fn vcpu(self) -> Option<usize> {
        match self {
            GicFrame::Dist => None,
            GicFrame::Redist(n) | GicFrame::Sgi(n) => Some(n),
        }
    }
}

impl GicLayout {
    /// A layout. Callers should satisfy [`GicLayout::validate`]; the decode is total either way, but
    /// only a valid layout decodes to the frames the names suggest.
    #[must_use]
    pub const fn new(gicd_base: u64, gicd_len: u64, gicr_rd_base: u64, gicr_end: u64) -> Self {
        Self {
            gicd_base,
            gicd_len,
            gicr_rd_base,
            gicr_end,
        }
    }

    /// Base of the distributor window.
    #[must_use]
    pub const fn gicd_base(&self) -> u64 {
        self.gicd_base
    }

    /// Length of the distributor window.
    #[must_use]
    pub const fn gicd_len(&self) -> u64 {
        self.gicd_len
    }

    /// Base of the redistributor window.
    #[must_use]
    pub const fn gicr_rd_base(&self) -> u64 {
        self.gicr_rd_base
    }

    /// End of the redistributor window.
    #[must_use]
    pub const fn gicr_end(&self) -> u64 {
        self.gicr_end
    }

    /// Whether this layout is one the decode can honour.
    ///
    /// **This is a precondition that used to be unwritten.** [`GicLayout::frame_of`] resolves an
    /// address below `gicr_rd_base` to the distributor, which only means what it says if the
    /// distributor's window actually ends at or before the redistributor's. Nothing in `hv-metal`
    /// ever stated that; it was true of the one board in play and would have failed silently on a
    /// second. Note the decode is **safe** regardless — it cannot underflow or index out of range
    /// for any layout at all — so this is about the decode being *right*, not about it being sound.
    ///
    /// ⑱-2 made the redistributor requirement a function of `vcpus`: **every** vCPU's pair of frames
    /// must fit, not just the first one's. A layout that housed one redistributor and was then asked
    /// for two would decode vCPU 1's frames to addresses past `gicr_end`, i.e. outside the window the
    /// guest was told about.
    #[must_use]
    pub const fn validate(&self, vcpus: usize) -> bool {
        // A GIC with no redistributor has no CPU interface at all; the decode below would also have
        // no frame to resolve into.
        if vcpus == 0 {
            return false;
        }
        // No arithmetic in the decode may wrap, ...
        let Some(gicd_end) = self.gicd_base.checked_add(self.gicd_len) else {
            return false;
        };
        // ... the two regions must not overlap (the distributor must end first), ...
        if gicd_end > self.gicr_rd_base {
            return false;
        }
        // ... and the redistributor region must be large enough for EVERY vCPU's pair of frames.
        let Some(span) = (vcpus as u64).checked_mul(GICR_FRAMES * GICR_FRAME) else {
            return false;
        };
        match self.gicr_rd_base.checked_add(span) {
            Some(need) => need <= self.gicr_end,
            None => false,
        }
    }

    /// `true` iff `ipa` falls in the emulated GIC's windows, so a caller's fault router sends it to
    /// this model rather than reporting an unexpected fault.
    #[must_use]
    pub const fn in_window(&self, ipa: u64) -> bool {
        (ipa >= self.gicd_base && ipa < self.gicd_base.wrapping_add(self.gicd_len))
            || (ipa >= self.gicr_rd_base && ipa < self.gicr_end)
    }

    /// Split a guest IPA into `(frame, offset within frame)`, or `None` if it is in no frame at all.
    ///
    /// The redistributor region `guest.dts` declares is much larger than the `vcpus` redistributors
    /// a guest actually has (it is sized for the machine's maximum CPU count). Everything past the
    /// last vCPU's SGI frame is therefore *in the window* but in no frame, and lands on the unhandled
    /// path — reported, not silently absorbed, because an access there means the guest believes in a
    /// redistributor that does not exist.
    ///
    /// ⚠ **⑱-2 made that sentence TRUE.** It was already the doc, but the code mapped every offset
    /// at or past the first RD frame to `Sgi` with an ever-growing offset; such an access was
    /// reported as unhandled *`GICR_SGI`* by falling off the end of that frame's register list rather
    /// than by being recognised as out of frame. With `vcpus` redistributors the arithmetic has to
    /// name one, so the bound is now checked and the answer is `None`.
    ///
    /// **Total, not caller-guarded.** This used to subtract `GICD_BASE` unconditionally, which
    /// UNDERFLOWS for any address below the distributor — wrapping in release to a huge offset that
    /// happened to fall through to the unhandled path. It failed closed by luck, and only because
    /// `in_window` — a *separate* function the caller had to remember — kept such an address out. A
    /// device model reached with a guest-derived address should not have preconditions its own entry
    /// points do not enforce.
    #[must_use]
    pub const fn frame_of(&self, ipa: u64, vcpus: usize) -> Option<(GicFrame, u64)> {
        if !self.in_window(ipa) {
            return None;
        }
        if ipa < self.gicr_rd_base {
            return Some((GicFrame::Dist, ipa - self.gicd_base));
        }
        let off = ipa - self.gicr_rd_base;
        // Which redistributor, and where within its pair of frames. The division cannot divide by
        // zero (`GICR_FRAMES * GICR_FRAME` is a non-zero constant) and `n` is bounds-checked against
        // `vcpus` before it is ever used as an index.
        let pair = GICR_FRAMES * GICR_FRAME;
        let n = off / pair;
        if n >= vcpus as u64 {
            return None;
        }
        let within = off % pair;
        let n = n as usize;
        Some(if within < GICR_FRAME {
            (GicFrame::Redist(n), within)
        } else {
            (GicFrame::Sgi(n), within - GICR_FRAME)
        })
    }
}

/// A guest MMIO access this model does not implement — reported to the caller with the syndrome, not
/// guessed at.
pub struct Unhandled {
    /// Which frame the access landed in, for the diagnostic.
    pub frame: &'static str,
    /// Offset within that frame.
    pub offset: u64,
}

/// The emulated GICv3 distributor + redistributor: one guest's interrupt-controller state, held in
/// memory the guest cannot reach.
///
/// **Register state only.** The trap and enable tallies the boot witness reports live in the caller;
/// the crate docs explain why a counter in here would make [`VirtGic::mmio_write`]'s fail-closed
/// guarantee unstateable.
///
/// `Clone`/`PartialEq` exist **for the proofs**: "a failed write changes nothing" is a statement
/// about two whole device states, so a harness has to be able to snapshot one and compare. They are
/// not used by the metal, and deriving them is what keeps the theorem a comparison of the *entire*
/// struct rather than of a hand-picked list of fields.
#[derive(Clone, PartialEq, Eq)]
pub struct VirtGic<const VCPUS: usize> {
    /// Where this distributor sits in the guest's address space.
    layout: GicLayout,
    /// `GICD_CTLR`, minus the bits this model forces ([`CTLR_ARE_NS`] on, `RWP` off).
    ctlr: u32,
    /// **One redistributor per vCPU**, each owning its own copy of INTIDs 0..31 (⑱-2).
    redist: [RedistBank; VCPUS],
    /// SPI enable bits. **The load-bearing state**: the caller consults it before forwarding a
    /// physical interrupt.
    ///
    /// ⚠ **Words below `FIRST_SPI / 32` are permanently zero and that is a theorem, not an
    /// intention.** INTIDs 0..31 are redistributor-banked and live in [`RedistBank`]; the
    /// distributor's decode refuses them (`dist_word_index`), which
    /// `the_distributor_cannot_reach_a_redistributor_banked_intid` proves. The arrays keep their
    /// full length so that every index is `intid / 32` with no rebasing arithmetic — a subtraction
    /// repeated at a dozen sites is exactly the sort of thing that goes wrong once.
    enabled: [u32; WORDS],
    /// Group assignment (1 = Group 1, which is all this port delivers). Same banking as `enabled`.
    group: [u32; WORDS],
    /// Per-INTID priority. Same banking as `enabled`.
    priority: [u8; NUM_INTIDS],
    /// Per-INTID configuration, 2 bits each: edge/level. Same banking as `enabled`.
    icfgr: [u32; NUM_INTIDS / 16],
    /// Per-SPI affinity routing. Recorded, not acted on — see the module docs' residue list.
    irouter: [u64; NUM_INTIDS - FIRST_SPI],
}

/// **One vCPU's redistributor** — its wake state and its own copy of INTIDs 0..31.
///
/// The architecture banks SGIs and PPIs per-PE, and that banking is the whole reason this type
/// exists: vCPU 0 enabling its timer PPI must not enable vCPU 1's. Before ⑱-2 these fields were word
/// 0 of the distributor's arrays, which is correct for exactly one vCPU and silently wrong for two —
/// design-lesson #150's shape, caught before the second tenant arrived rather than after.
#[derive(Clone, Copy, PartialEq, Eq)]
struct RedistBank {
    /// `GICR_WAKER.ProcessorSleep`. Starts asleep, as a redistributor does out of reset. **Per
    /// redistributor**: each vCPU performs its own wake handshake as it comes up.
    asleep: bool,
    /// Enable bits for this vCPU's INTIDs 0..31.
    enabled: u32,
    /// Group assignment for this vCPU's INTIDs 0..31.
    group: u32,
    /// Priority for this vCPU's INTIDs 0..31.
    priority: [u8; FIRST_SPI],
    /// Edge/level configuration, 2 bits per INTID, for this vCPU's INTIDs 0..31.
    icfgr: [u32; FIRST_SPI / 16],
}

impl RedistBank {
    const AT_RESET: Self = Self {
        asleep: true,
        enabled: 0,
        group: 0,
        priority: [0; FIRST_SPI],
        icfgr: [0; FIRST_SPI / 16],
    };
}

impl<const VCPUS: usize> VirtGic<VCPUS> {
    /// A distributor out of reset: everything disabled, every redistributor asleep.
    #[must_use]
    pub const fn new(layout: GicLayout) -> Self {
        // `GICR_TYPER.Processor_Number` is bits [15:8] — eight of them. A `VCPUS` past 255 would
        // shift a processor number straight through that field into the reserved bits above it, and
        // every redistributor from 256 on would report a number that is not its own. Nothing else in
        // the model has an opinion about the count, so this is where the ceiling belongs: an
        // instantiation that exceeds it does not compile, rather than producing a device whose
        // registers quietly disagree with each other.
        //
        // (The AFFINITY field does not need this. `Aff0` overflowing into `Aff1` is what a packed
        // affinity is supposed to do, and `hv-metal`'s `guest_mpidr` packs it the same way, so the
        // two stay in agreement past 255 even though the processor number would not.)
        const {
            assert!(
                VCPUS <= 255,
                "GICR_TYPER.Processor_Number is eight bits wide"
            )
        };
        Self {
            layout,
            ctlr: 0,
            redist: [RedistBank::AT_RESET; VCPUS],
            enabled: [0; WORDS],
            group: [0; WORDS],
            priority: [0; NUM_INTIDS],
            icfgr: [0; NUM_INTIDS / 16],
            irouter: [0; NUM_INTIDS - FIRST_SPI],
        }
    }

    /// **Is `intid` enabled for `vcpu`, in the guest's own interrupt controller?** The mediation
    /// seam: EL2 forwards a physical interrupt only when the guest has asked for it, rather than
    /// whenever one arrives.
    ///
    /// ⑱-2 added the `vcpu` argument, and it is not decoration: **INTIDs 0..31 are banked per
    /// redistributor**, so "is the timer PPI enabled" has a different answer per vCPU and the caller
    /// must say which one it is asking about. SPIs live in the distributor and are shared, so the
    /// argument does not affect them. An out-of-range `vcpu` or `intid` reads as **not enabled**,
    /// which is the fail-closed direction: EL2 declines to forward.
    #[must_use]
    pub fn is_enabled(&self, vcpu: usize, intid: u32) -> bool {
        let i = intid as usize;
        if i >= NUM_INTIDS {
            return false;
        }
        if i < FIRST_SPI {
            return match self.redist.get(vcpu) {
                Some(r) => r.enabled & (1 << i) != 0,
                None => false,
            };
        }
        self.enabled[i / 32] & (1 << (i % 32)) != 0
    }

    /// **Where the guest routed `intid`** — the second mediation seam, beside [`Self::is_enabled`].
    ///
    /// ⑱-6. `is_enabled` answers *whether* EL2 forwards an interrupt; this answers *to which vCPU*.
    /// Both read state the guest itself wrote, which is the point: the routing is the guest's
    /// decision, and EL2's job is to honour it rather than to have a policy of its own.
    ///
    /// `None` for anything that is not an SPI — INTIDs 0..31 are redistributor-banked and have no
    /// `IROUTER` entry at all, so there is nothing here to consult and the caller already knows
    /// which vCPU a banked interrupt belongs to. Fail-closed in the same direction as `is_enabled`:
    /// a caller handed `None` must not invent a target.
    #[must_use]
    pub fn spi_route(&self, intid: u32) -> Option<crate::irouter::SpiRoute> {
        let i = intid as usize;
        if !(FIRST_SPI..NUM_INTIDS).contains(&i) {
            return None;
        }
        Some(crate::irouter::decode(self.irouter[i - FIRST_SPI]))
    }

    /// `GICR_TYPER` as vCPU `n` sees it — affinity, processor number, and **`Last` on exactly the
    /// final redistributor**.
    ///
    /// A guest discovers its redistributors by walking the region and reading this until it finds
    /// `Last`. Setting it on none makes the walk run off the end of the window; setting it on more
    /// than one truncates the walk early, so a later vCPU never finds its frame and does not come up.
    /// `the_last_redistributor_is_the_only_one_that_says_so` pins both halves.
    #[must_use]
    pub const fn gicr_typer(n: usize) -> u64 {
        let last = if n + 1 == VCPUS { GICR_TYPER_LAST } else { 0 };
        last | ((n as u64) << GICR_TYPER_PROC_SHIFT) | (vcpu_affinity(n) << GICR_TYPER_AFF_SHIFT)
    }

    /// Service a guest **read** of the emulated GIC at `ipa`, `size` bytes wide.
    ///
    /// Takes `&self`: servicing a read cannot change this device. That is worth stating as a
    /// signature rather than a comment — it was `&mut self` until ⑯, purely because a witness
    /// counter lived in the struct.
    pub fn mmio_read(&self, ipa: u64, size: u64) -> Result<u64, Unhandled> {
        let Some((frame, off)) = self.layout.frame_of(ipa, VCPUS) else {
            return Err(Unhandled {
                frame: "outside every emulated GIC frame",
                offset: ipa,
            });
        };
        match frame {
            GicFrame::Dist => self.dist_read(off, size),
            GicFrame::Redist(n) => self.redist_read(n, off),
            GicFrame::Sgi(n) => self.sgi_read(n, off),
        }
        .ok_or(Unhandled {
            frame: frame.name(),
            offset: off,
        })
    }

    /// Service a guest **write** of the emulated GIC at `ipa`, `size` bytes wide.
    ///
    /// On success returns **how many INTIDs this write newly enabled** — information the caller
    /// needs and the model does not keep, the same shape as the PL011 model reporting a transmitted
    /// byte. On `Err` the model's state is unchanged, which is what lets a caller park on an
    /// unmodelled register without wondering whether half of it was applied.
    pub fn mmio_write(&mut self, ipa: u64, size: u64, value: u64) -> Result<u32, Unhandled> {
        let Some((frame, off)) = self.layout.frame_of(ipa, VCPUS) else {
            return Err(Unhandled {
                frame: "outside every emulated GIC frame",
                offset: ipa,
            });
        };
        match frame {
            GicFrame::Dist => self.dist_write(off, size, value),
            GicFrame::Redist(n) => self.redist_write(n, off, value as u32),
            GicFrame::Sgi(n) => self.sgi_write(n, off, value as u32),
        }
        .ok_or(Unhandled {
            frame: frame.name(),
            offset: off,
        })
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

    /// Returns `Some(newly enabled INTIDs)` when the offset is one this frame models.
    fn dist_write(&mut self, off: u64, _size: u64, value: u64) -> Option<u32> {
        if let Some(i) = irouter_index(off) {
            self.irouter[i] = value;
            return Some(0);
        }
        let v = value as u32;
        match off {
            GICD_CTLR => {
                self.ctlr = v & CTLR_WRITABLE;
                return Some(0);
            }
            // The identification registers are read-only; a write to them is a guest bug, not ours.
            GICD_TYPER | GICD_IIDR | GICD_TYPER2 | GICD_PIDR2 => return Some(0),
            _ => {}
        }
        if let Some(w) = dist_word_index(off, GICD_IGROUPR, WORDS, 32) {
            self.group[w] = v;
            return Some(0);
        }
        if let Some(w) = dist_word_index(off, GICD_ISENABLER, WORDS, 32) {
            return Some(self.set_enabled(w, v));
        }
        if let Some(w) = dist_word_index(off, GICD_ICENABLER, WORDS, 32) {
            self.enabled[w] &= !v;
            return Some(0);
        }
        if dist_word_index(off, GICD_ISPENDR, WORDS, 32).is_some()
            || dist_word_index(off, GICD_ICPENDR, WORDS, 32).is_some()
            || dist_word_index(off, GICD_ISACTIVER, WORDS, 32).is_some()
            || dist_word_index(off, GICD_ICACTIVER, WORDS, 32).is_some()
        {
            return Some(0); // declared residue
        }
        if let Some(w) = dist_word_index(off, GICD_ICFGR, NUM_INTIDS / 16, 16) {
            self.icfgr[w] = v;
            return Some(0);
        }
        if (GICD_IPRIORITYR + FIRST_SPI as u64..GICD_IPRIORITYR + NUM_INTIDS as u64).contains(&off)
        {
            let base = (off - GICD_IPRIORITYR) as usize & !3;
            for k in 0..4 {
                self.priority[base + k] = (value >> (8 * k)) as u8;
            }
            return Some(0);
        }
        None
    }

    // ─── the redistributor's RD frame ────────────────────────────────────────────────────────────

    /// `n` is in range for `redist`: [`GicLayout::frame_of`] checked it against `VCPUS` before
    /// naming this frame, which is why the index below is not re-checked here.
    fn redist_read(&self, n: usize, off: u64) -> Option<u64> {
        let bank = self.redist.get(n)?;
        let v = match off {
            GICR_CTLR => 0u64,
            GICR_IIDR => BALEEN_IIDR as u64,
            GICR_TYPER => Self::gicr_typer(n),
            GICR_WAKER => {
                if bank.asleep {
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

    fn redist_write(&mut self, n: usize, off: u64, value: u32) -> Option<u32> {
        let bank = self.redist.get_mut(n)?;
        match off {
            // `ChildrenAsleep` is read-only; only `ProcessorSleep` is taken from the write, and the
            // read side mirrors it so the guest's wake handshake terminates.
            GICR_WAKER => {
                bank.asleep = value & WAKER_PROCESSOR_SLEEP != 0;
                Some(0)
            }
            GICR_CTLR | GICR_IIDR | GICR_TYPER | GICR_PIDR2 => Some(0),
            _ => None,
        }
    }

    // ─── the redistributor's SGI frame: INTIDs 0..31, this vCPU's SGIs and PPIs ──────────────────

    /// **Every field read here comes from `redist[n]`, not from the distributor's arrays.** That is
    /// the whole of ⑱-2's state change: before it, these were word 0 of the shared banks, so two
    /// vCPUs' SGI frames would have aliased onto one another's enables.
    fn sgi_read(&self, n: usize, off: u64) -> Option<u64> {
        let bank = self.redist.get(n)?;
        let v = match off {
            GICR_IGROUPR0 => bank.group,
            GICR_ISENABLER0 | GICR_ICENABLER0 => bank.enabled,
            // Declared residue, as in the distributor.
            GICR_ISPENDR0 | GICR_ICPENDR0 | GICR_ISACTIVER0 | GICR_ICACTIVER0 => 0,
            GICR_ICFGR0 => bank.icfgr[0],
            GICR_ICFGR1 => bank.icfgr[1],
            _ => {
                if (GICR_IPRIORITYR..GICR_IPRIORITYR + FIRST_SPI as u64).contains(&off) {
                    let base = (off - GICR_IPRIORITYR) as usize & !3;
                    let mut v = 0u32;
                    for k in 0..4 {
                        v |= (bank.priority[base + k] as u32) << (8 * k);
                    }
                    v
                } else {
                    return None;
                }
            }
        };
        Some(v as u64)
    }

    fn sgi_write(&mut self, n: usize, off: u64, value: u32) -> Option<u32> {
        let bank = self.redist.get_mut(n)?;
        match off {
            GICR_IGROUPR0 => bank.group = value,
            GICR_ISENABLER0 => {
                let newly = value & !bank.enabled;
                bank.enabled |= value;
                return Some(newly.count_ones());
            }
            GICR_ICENABLER0 => bank.enabled &= !value,
            GICR_ISPENDR0 | GICR_ICPENDR0 | GICR_ISACTIVER0 | GICR_ICACTIVER0 => {}
            GICR_ICFGR0 => bank.icfgr[0] = value,
            GICR_ICFGR1 => bank.icfgr[1] = value,
            _ => {
                if (GICR_IPRIORITYR..GICR_IPRIORITYR + FIRST_SPI as u64).contains(&off) {
                    let base = (off - GICR_IPRIORITYR) as usize & !3;
                    for k in 0..4 {
                        bank.priority[base + k] = (value >> (8 * k)) as u8;
                    }
                } else {
                    return None;
                }
            }
        }
        Some(0)
    }

    /// Set enable bits in bank `w`, returning how many INTIDs were **newly** enabled.
    ///
    /// The count is the caller's witness's discriminating half: it is a statement about the guest
    /// having programmed THIS distributor, which a pass-through configuration could not produce
    /// because the writes would never have been seen. It is *returned* rather than accumulated here
    /// — see the crate docs on why witness state does not live in the model.
    fn set_enabled(&mut self, w: usize, bits: u32) -> u32 {
        let newly = bits & !self.enabled[w];
        self.enabled[w] |= bits;
        newly.count_ones()
    }
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

/// If `off` names a word of a DISTRIBUTOR bank, its index — **excluding the redistributor-banked
/// words**.
///
/// **The distributor does not own INTIDs 0..31.** With `GICD_CTLR.ARE_NS` set (which this model
/// forces), SGIs and PPIs are banked *per redistributor*, and the distributor's copies of them are
/// RES0. Before this guard `GICD_ISENABLER0` and `GICR_ISENABLER0` both reached `enabled[0]`, so a
/// write the architecture reserves could change the guest's PPI enables — and, worse for the proofs,
/// it meant the two frames deliberately SHARED state, which makes **"the decode is a partition"
/// false as a theorem** rather than merely hard to state.
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
