// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The vGIC **CPU interface** — the list-register algebra, under the fence (⑰-b′)
//!
//! ## The gap this closes, and it is not the one ⑯ closed
//!
//! ⑯ brought the guest's device models here: the emulated distributor and redistributor
//! ([`crate::gicv3`]), which is **what the guest drives** through trapped MMIO. That left the other
//! half of the same device untouched. A virtual interrupt does not reach a guest through the
//! distributor model at all — EL2 writes it into a **list register** (`ICH_LR<n>_EL2`), a per-vCPU
//! hardware register whose 64 bits encode a state, a group, a priority, a virtual INTID, and
//! optionally a mapping to a *physical* interrupt. That encoding, its decode, and the transform a
//! context switch applies to a saved bank were `hv-metal`'s alone, and `hv-metal` is
//! workspace-EXCLUDED — structurally unreachable by Kani.
//!
//! So the surface split in an awkward place: **what the guest reads was proven, what EL2 writes was
//! not**, and the switch operates entirely on the unproven half.
//!
//! ## Why this half is worth a theorem — it has a defect history, not just a gap
//!
//! ③-b2b-ii-c1's witness claimed exactly one hardware mapping demoted per switch and measured
//! **119 against an expected 60**. The cause is the sharpest fact in this module: **an Invalid list
//! register is not a zeroed one.** `place` overwrites a free slot wholesale when it reuses it, so a
//! *completed* injection leaves its `HW` bit and its `pINTID` lying in the bank until something else
//! is placed there. Demoting such a slot is inert — an Invalid LR is neither presented to the guest
//! nor matched by its EOI — but it destroys the count, and the count was the witness.
//!
//! The fix was to test [`lr_is_free`] **first**. That is one `!` in a condition, it is invisible to
//! every boot that does not count, and it is exactly the kind of thing a theorem holds still.
//!
//! ## What is here and what deliberately is not — ⑯'s split, applied again
//!
//! **Here: the algebra.** The field layout, the encoder, the decoders, and
//! [`release_hardware_mappings`] — the transform a switch applies to a *saved* bank, which is
//! ordinary memory and so needs no hardware to describe.
//!
//! **Not here, and each for the reason ⑯ gave:**
//!
//! 1. **`ICH_LR<n>_EL2` itself.** Reading and writing a list register is an `mrs`/`msr` against a
//!    register named by a string literal; that is `unsafe` asm, which this crate forbids. It stays in
//!    `hv-metal`'s `gic.rs`, and keeping it at the call site is what lets this module be pure.
//! 2. **How many list registers exist.** `num_list_registers()` reads `ICH_VTR_EL2` — a claim about
//!    *this machine* (4 on QEMU `virt`), not about the architecture. [`MAX_LIST_REGISTERS`] is here
//!    because the ceiling of 16 is architectural; the live count is the metal's to discover, and it
//!    arrives here only as the length of the slice a caller passes.
//! 3. **Which priority an injection gets.** `INJECT_PRIORITY = 0x80` is a policy choice justified by
//!    the mask the guest is expected to run with, so [`encode_lr`] takes it as a parameter rather than
//!    baking it in — the same call `GicLayout` makes for the board's addresses.
//!
//! ## The honest ceiling, stated before the theorems rather than after
//!
//! These proofs are about the **algebra**. They do not say that the value this module encodes is the
//! one that reaches the hardware register — `hv-metal` is still not a Kani target, so that remains a
//! construction argument.
//!
//! **On the bank's length, be precise, because the obvious sentence is wrong in both directions.**
//! What IS proven: the transform behaves correctly for *every* prefix length 0..=16, and touches
//! nothing beyond the prefix it was given. What is NOT: that `hv-metal` computes the right length —
//! it reads `ICH_VTR_EL2` and slices to it, and no theorem here can see that read. So the residual is
//! narrower than "the prefix is unproven": it is exactly one value, obtained from one register.
//!
//! And, exactly as ⑯ declared for the distributor: this is **structure, not GICv3 conformance.**
//! Nothing here checks the field positions against the Arm ARM; it checks that whatever this module
//! encodes, it decodes, and that the switch's transform touches what it claims to touch and nothing
//! else.

/// The architectural maximum number of list registers — GICv3 implements at most 16 (`ICH_LR0..15`).
///
/// A *ceiling*, not a count: how many are live is a property of the machine (`ICH_VTR_EL2`), which
/// this crate cannot read and deliberately does not model. It is here because a per-vCPU bank must be
/// sized to something at compile time, and the architecture is what bounds it.
pub const MAX_LIST_REGISTERS: usize = 16;

// ─── ICH_LR<n>_EL2 field layout (GICv3 list register) ────────────────────────────────────────────

/// vINTID — the virtual interrupt id the guest sees, bits [31:0].
const LR_VINTID_SHIFT: u32 = 0;
/// Width of the vINTID field.
const LR_VINTID_BITS: u32 = 32;
/// `pINTID`, bits [41:32] — the **physical** INTID a `HW=1` list register is mapped to.
const LR_PINTID_SHIFT: u32 = 32;
/// Width of the `pINTID` field. Ten bits, so it names INTIDs 0..=1023 (the SGI/PPI/SPI range); LPIs
/// are out of its reach and out of this port's scope.
const LR_PINTID_BITS: u32 = 10;
/// Priority, bits [55:48] (only the top `ICH_VTR_EL2.PRIbits` are architecturally significant, which
/// is a property of the machine — this module carries the whole field).
const LR_PRIORITY_SHIFT: u32 = 48;
/// Width of the priority field.
const LR_PRIORITY_BITS: u32 = 8;
/// Group, bit [60] — 1 = Group 1, acknowledged by the guest via `ICC_IAR1_EL1`.
const LR_GROUP1: u64 = 1 << 60;
/// `HW`, bit [61] — this virtual interrupt is **mapped to a physical one**, named by `pINTID`.
///
/// The bit exists because a forwarded *level-triggered* interrupt has a physical lifecycle only a
/// deactivate ends, and EL2 gets no signal when the guest has serviced the device and dropped the
/// level. `HW=1` delegates that: the guest's EOI of the **virtual** interrupt deactivates the
/// **physical** one, with no EL2 involvement. See [`release_hardware_mappings`] for the one moment
/// that delegation has to be taken back.
const LR_HW: u64 = 1 << 61;
/// The **State** field, bits [63:62].
const LR_STATE_SHIFT: u32 = 62;
/// Width of the State field.
const LR_STATE_BITS: u32 = 2;

/// A mask of `bits` wide at `shift`.
const fn field_mask(shift: u32, bits: u32) -> u64 {
    // `bits` is never 64 for any field here, so the shift cannot overflow.
    ((1u64 << bits) - 1) << shift
}

/// Extract a field.
const fn field(lr: u64, shift: u32, bits: u32) -> u64 {
    (lr >> shift) & ((1u64 << bits) - 1)
}

/// The largest physical INTID a `HW=1` list register can name.
///
/// An INTID that does not fit **cannot be named**, which is why [`encode_lr`] returns [`None`] rather
/// than masking: a truncated `pINTID` would name a *different* physical interrupt, so the guest's EOI
/// would deactivate someone else's — silent, and far worse than a refusal the caller reports.
pub const MAX_PINTID: u32 = (1 << LR_PINTID_BITS) - 1;

/// The state of a virtual interrupt in a list register (`ICH_LR<n>_EL2.State`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LrState {
    /// `0b00` — the list register holds no interrupt. A **free slot** an injector may allocate.
    Invalid,
    /// `0b01` — pending: the guest has not taken it yet.
    Pending,
    /// `0b10` — active: the guest has acknowledged it and not yet ended it.
    Active,
    /// `0b11` — pending and active at once (a second assertion arrived while the first was active).
    PendingActive,
}

/// Decode a list register's State field.
pub const fn lr_state(lr: u64) -> LrState {
    match field(lr, LR_STATE_SHIFT, LR_STATE_BITS) {
        0b00 => LrState::Invalid,
        0b01 => LrState::Pending,
        0b10 => LrState::Active,
        _ => LrState::PendingActive,
    }
}

/// A list register with State = Invalid holds no interrupt — a free slot an injector may allocate.
///
/// **The distinction this function exists to make**, and the one that cost a witness: free means
/// *State is Invalid*, not *the register is zero*. Every other field of a free slot may hold the
/// residue of a completed injection.
pub const fn lr_is_free(lr: u64) -> bool {
    matches!(lr_state(lr), LrState::Invalid)
}

/// Whether this list register carries a mapping to a physical interrupt (`HW`).
pub const fn lr_is_hw(lr: u64) -> bool {
    lr & LR_HW != 0
}

/// Whether this list register is Group 1.
pub const fn lr_is_group1(lr: u64) -> bool {
    lr & LR_GROUP1 != 0
}

/// The virtual INTID this list register carries.
pub const fn lr_vintid(lr: u64) -> u32 {
    field(lr, LR_VINTID_SHIFT, LR_VINTID_BITS) as u32
}

/// The priority this list register carries.
pub const fn lr_priority(lr: u64) -> u8 {
    field(lr, LR_PRIORITY_SHIFT, LR_PRIORITY_BITS) as u8
}

/// The **physical** INTID this list register is mapped to, or [`None`] if it carries no mapping.
///
/// Returning an `Option` rather than the raw field is the point. With `HW=0` those bits are **not** a
/// spare copy of a physical INTID: bit 41 is `EOI` (request a maintenance interrupt when the guest
/// ends this interrupt) and bits 40:32 are RES0. Reading them as a `pINTID` when `HW` is clear would
/// be reading a different register's meaning.
pub const fn lr_pintid(lr: u64) -> Option<u32> {
    if lr_is_hw(lr) {
        Some(field(lr, LR_PINTID_SHIFT, LR_PINTID_BITS) as u32)
    } else {
        None
    }
}

/// **The one list-register encoder.** Build a *pending* Group-1 list register for `vintid`.
///
/// `hw` is `Some(pintid)` for a **forwarded** physical interrupt — the guest's EOI of the virtual
/// interrupt will deactivate that physical one — and [`None`] for a purely virtual interrupt the
/// guest invented (an SGI it sent itself), where a hardware mapping would be a lie.
///
/// Returns [`None`] when `pintid` exceeds [`MAX_PINTID`]. The refusal lives *in the encoder* rather
/// than at the call site so that an out-of-range `pINTID` is unrepresentable rather than merely
/// rejected by whoever remembered to check.
pub const fn encode_lr(vintid: u32, hw: Option<u32>, priority: u8) -> Option<u64> {
    let base = (0b01 << LR_STATE_SHIFT)
        | LR_GROUP1
        | ((priority as u64) << LR_PRIORITY_SHIFT)
        | ((vintid as u64) << LR_VINTID_SHIFT);
    match hw {
        Some(pintid) => {
            if pintid > MAX_PINTID {
                None
            } else {
                Some(base | LR_HW | ((pintid as u64) << LR_PINTID_SHIFT))
            }
        }
        None => Some(base),
    }
}

/// Build a list register in the **Active** state — occupied, but never presented to the guest.
///
/// The three-line reason this exists: a list register is "free" iff its State is Invalid, and only a
/// **Pending** one is offered to the guest's CPU interface. An Active entry therefore fills a slot —
/// [`lr_is_free`] refuses it, so an injector skips it — while being invisible to the guest.
///
/// That is exactly what a test needs to manufacture a full bank without handing the guest an
/// interrupt it did not ask for. It is here rather than open-coded at the call site because the State
/// field's position is this module's fact, and ⑰-b′ exists so there is only one copy of it.
pub const fn encode_active(vintid: u32) -> u64 {
    (0b10 << LR_STATE_SHIFT) | ((vintid as u64) << LR_VINTID_SHIFT)
}

/// **Strip the hardware mapping from every occupied list register in a saved bank**, returning how
/// many were converted (③-b2b-ii-c1).
///
/// ## Why a forwarded interrupt cannot cross a context switch as a forwarded interrupt
///
/// `HW=1` is a promise about a *physical* interrupt: the guest's EOI of this virtual one will
/// deactivate `pINTID`. There is one physical timer PPI on this machine and it is about to belong to
/// a different vCPU, so the promise stops being true the moment the switch happens — and honouring it
/// later would have the **incoming** guest's EOI deactivate an interrupt the **outgoing** one was
/// given. EL2 therefore deactivates the physical interrupt itself and demotes what it saved to a
/// purely virtual pending interrupt, which is exactly what it now is: something the guest still has
/// to take and end, with nothing physical hanging off it.
///
/// The outgoing guest loses nothing. Its interrupt is still pending in its own bank at its own
/// priority; when it is resumed, its still-expired deadline re-asserts the level and EL2 forwards a
/// fresh one. What it gives up is ownership of a line it is not running on.
///
/// ## Two things this does that a shorter implementation would not
///
/// **[`lr_is_free`] is tested first, and it is not an optimization.** See the module docs: a
/// completed injection leaves `HW` and `pINTID` behind in an Invalid slot, and demoting those is
/// inert but uncountable. Measured at 119 demotions against an expected 60.
///
/// **`pINTID` is cleared, not left behind.** With `HW=0` those bits are not spare — bit 41 becomes
/// `EOI` and bits 40:32 are RES0. Leaving a physical INTID there would write a nonzero RES0 field,
/// and for a wide enough INTID would arm a maintenance interrupt nobody handles.
///
/// ## What survives, and why that is safe — stated because a proof refuted the tidier claim
///
/// Because free slots are skipped, **a completed injection's `HW` bit and `pINTID` survive the
/// release.** The obvious property — "no list register carries a hardware mapping afterwards" — is
/// therefore FALSE, and Kani says so with a counterexample rather than leaving it to a reader.
///
/// What is true, and is what the proof states: **a surviving mapping can only be in a free slot.** An
/// Invalid list register is neither presented to the guest nor matched by its EOI, so the incoming
/// guest cannot reach it; and when the injector reuses that slot it writes the whole 64-bit encoding
/// at once, so no residue is ever partially inherited. The safety argument is confinement, not
/// erasure — worth saying in those words, because the erasure claim reads better and is wrong.
///
/// `bank` is the **live prefix** of a saved bank; how long that is, is the caller's to know.
pub fn release_hardware_mappings(bank: &mut [u64]) -> u64 {
    const PINTID_FIELD: u64 = field_mask(LR_PINTID_SHIFT, LR_PINTID_BITS);
    let mut released = 0;
    for lr in bank.iter_mut() {
        if !lr_is_free(*lr) && lr_is_hw(*lr) {
            *lr &= !(LR_HW | PINTID_FIELD);
            released += 1;
        }
    }
    released
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_free_list_register_need_not_be_zero() {
        // The 119/60 case in one line: a completed injection's residue.
        let stale = encode_lr(27, Some(27), 0x80).unwrap() & !(0b11 << LR_STATE_SHIFT);
        assert!(lr_is_free(stale));
        assert!(lr_is_hw(stale));
    }

    #[test]
    fn release_skips_free_slots_and_counts_only_what_it_demoted() {
        let occupied = encode_lr(27, Some(27), 0x80).unwrap();
        let stale = occupied & !(0b11 << LR_STATE_SHIFT);
        let mut bank = [occupied, stale, encode_lr(33, None, 0x80).unwrap()];
        assert_eq!(release_hardware_mappings(&mut bank), 1);
        assert_eq!(bank[1], stale, "a free slot is left exactly as it was");
        assert!(!lr_is_hw(bank[0]));
        assert_eq!(lr_vintid(bank[0]), 27);
    }

    #[test]
    fn an_out_of_range_physical_intid_is_refused_not_truncated() {
        assert!(encode_lr(27, Some(MAX_PINTID), 0x80).is_some());
        assert!(encode_lr(27, Some(MAX_PINTID + 1), 0x80).is_none());
    }

    #[test]
    fn an_encoded_list_register_is_never_free() {
        // What makes `place` correct: it never writes a value the next injection would reuse.
        assert!(!lr_is_free(encode_lr(0, None, 0).unwrap()));
        assert!(!lr_is_free(encode_lr(0, Some(0), 0).unwrap()));
    }
}
