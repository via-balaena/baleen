// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # `ICC_SGI1R_EL1` — the register a guest writes to raise an interrupt on another CPU (⑱-5)
//!
//! ## Why this is EL2's problem at all, and why it cannot stay degenerate
//!
//! `HCR_EL2.IMO=1` redirects a guest's interrupt-*handling* `ICC_*` accesses to the virtual CPU
//! interface, but **not** this one. Generating an SGI names its targets by **physical affinity** —
//! `Aff3.Aff2.Aff1` plus a 16-bit target list over `Aff0`, or "every PE but me" — and that is a
//! statement about real processing elements which a guest must not be allowed to make. So the
//! architecture traps the write to EL2 and the hypervisor decides what it means. **The trap is
//! unavoidable under `IMO=1`; it is not something this port opted into.**
//!
//! Until ⑱-5 the metal read **bits `[27:24]` only** — the INTID — and its own doc said so plainly:
//! *"The affinity fields are deliberately not read, because with a single vCPU there is no other
//! target they could name."* That was true and is now false. `VCPUS_PER_GUEST` is 2, so the fields
//! name something, and reading only the INTID means **every IPI is delivered to whichever vCPU
//! happens to be running.**
//!
//! ⚠ **MEASURED, on a probe that was reverted (design-lesson #161).** With a second vCPU actually
//! started, both guests reach `SMP: Total of 2 processors activated` and then fail at shutdown with
//! `SMP: failed to stop secondary CPUs 1` — `smp_send_stop`'s IPI to CPU 1 arriving at CPU 0 — and
//! the boot gate **times out**. That is the whole reason this rung goes *before* the one that starts
//! a second vCPU.
//!
//! ## What is here: a pure function of a guest-controlled `u64`
//!
//! This module decides **which PEs an SGI names**, and nothing else. No delivery, no pending set, no
//! list register — those need the machine and live in `hv-metal`. The split is the crate's stated
//! criterion: *"it is a pure function of ordinary state, so a theorem about it is statable"*.
//!
//! **And the input is chosen by the guest**, which is what makes a theorem worth having: the value
//! is 64 bits of whatever a kernel puts in a register, and this code turns it into a decision about
//! which vCPU receives an interrupt. `hv-verify` quantifies over all of it.
//!
//! ## ★ The one design decision, and it is what keeps the derivation single
//!
//! [`SgiTargets::targets`] takes a **packed affinity**, not a vCPU index — exactly what
//! [`vcpu_affinity`](crate::gicv3::vcpu_affinity) returns. So the caller writes
//! `decoded.targets(vcpu_affinity(v))` and this module never learns baleen's vCPU→affinity mapping.
//! That matters because the mapping already has exactly one derivation (⑱-3b-i closed a case where
//! it had two, in two crates, with a doc claiming otherwise), and a decode that re-derived "Aff0 is
//! the vCPU index" would be the third.
//!
//! It also makes the isolation property fall out rather than be checked: a guest naming a cluster no
//! vCPU of its own is in — any non-zero `Aff1`/`Aff2`/`Aff3` — targets **nothing**, because no
//! `vcpu_affinity` value can equal what it asked for.
//!
//! ## Bounds, and why there is no indexing here
//!
//! [`SgiTargets::targets`] is a **predicate**, not a list. The caller iterates the vCPUs it has and
//! asks about each, so "a target is always a vCPU that exists" is true by the shape of the call
//! rather than by a proof obligation — there is no index to get wrong and no array to run off. The
//! harnesses are therefore free to be about *meaning* (which PEs are named) instead of safety.

/// `ICC_SGI1R_EL1.INTID`, bits `[27:24]` — an SGI id, so 0..=15.
const INTID_SHIFT: u32 = 24;
const INTID_MASK: u64 = 0xf;
/// `IRM`, bit [47] — **1 = every PE except the one issuing the write**, and the affinity and target
/// list fields are then ignored entirely.
const IRM_BIT: u64 = 1 << 47;
/// `Aff1` `[23:16]`, `Aff2` `[39:32]`, `Aff3` `[63:56]` — one byte each, at three unrelated offsets.
const AFF1_SHIFT: u32 = 16;
const AFF2_SHIFT: u32 = 32;
const AFF3_SHIFT: u32 = 56;
const AFF_BYTE: u64 = 0xff;
/// `RS` (Range Selector), bits `[43:40]` — which block of 16 `Aff0` values the target list covers.
const RS_SHIFT: u32 = 40;
const RS_MASK: u64 = 0xf;
/// `TargetList`, bits `[15:0]` — bit `n` selects the PE whose `Aff0` is `RS * 16 + n`.
const TARGET_LIST_MASK: u64 = 0xffff;
/// How many `Aff0` values one target list covers.
const TARGETS_PER_RANGE: u64 = 16;
/// `Aff0` occupies the low byte of a packed affinity; the rest is the cluster.
const AFF0_MASK: u64 = 0xff;

/// **Which PEs one `ICC_SGI1R_EL1` write names**, decoded once and then asked about.
///
/// Deliberately not an iterator or a bitmask: see the module docs. A bitmask would have to be as
/// wide as the largest vCPU count the model allows (⑱-2 caps it at 255, because
/// `GICR_TYPER.Processor_Number` is 8 bits), and a broadcast names all of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SgiTargets {
    /// The SGI id, bits `[27:24]`.
    intid: u32,
    /// `IRM` — "all but me".
    broadcast: bool,
    /// The issuing PE's packed affinity, so a broadcast can exclude it.
    sender: u64,
    /// `Aff3:Aff2:Aff1` repacked into [`vcpu_affinity`]'s layout, with `Aff0` zero.
    cluster: u64,
    /// The lowest `Aff0` the target list covers (`RS * 16`).
    range_base: u64,
    /// The target list itself, bits `[15:0]`.
    list: u64,
}

/// Decode a guest's `ICC_SGI1R_EL1` write.
///
/// `sender` is the packed affinity of the vCPU that issued it — `vcpu_affinity(running_vcpu)` —
/// needed only so that a broadcast can exclude it, which the architecture requires.
#[must_use]
pub const fn decode(value: u64, sender: u64) -> SgiTargets {
    let aff1 = (value >> AFF1_SHIFT) & AFF_BYTE;
    let aff2 = (value >> AFF2_SHIFT) & AFF_BYTE;
    let aff3 = (value >> AFF3_SHIFT) & AFF_BYTE;
    SgiTargets {
        intid: ((value >> INTID_SHIFT) & INTID_MASK) as u32,
        broadcast: value & IRM_BIT != 0,
        sender,
        // Repacked into `vcpu_affinity`'s layout — one byte per level, `Aff0` lowest — because that
        // is what `targets` compares against. The register's three offsets are the register's
        // business and stop here.
        cluster: (aff1 << 8) | (aff2 << 16) | (aff3 << 24),
        range_base: ((value >> RS_SHIFT) & RS_MASK) * TARGETS_PER_RANGE,
        list: value & TARGET_LIST_MASK,
    }
}

impl SgiTargets {
    /// The SGI id this write raises — bits `[27:24]`, so always 0..=15.
    #[must_use]
    pub const fn intid(&self) -> u32 {
        self.intid
    }

    /// Whether this write used `IRM` ("every PE but me").
    ///
    /// The routing decision itself is [`Self::targets`], which already accounts for `IRM` — so this
    /// exists for the **harness**, not for a caller in `hv-metal`:
    /// `a_broadcast_names_every_vcpu_but_the_sender` asserts it to show the mode was recognised
    /// before asserting what it means, so that a decode which quietly never saw `IRM` at all could
    /// not satisfy the property vacuously.
    #[must_use]
    pub const fn is_broadcast(&self) -> bool {
        self.broadcast
    }

    /// **Does this SGI name the PE whose packed affinity is `aff`?**
    ///
    /// Pass [`vcpu_affinity(v)`](crate::gicv3::vcpu_affinity) — never a bare vCPU index. See the
    /// module docs for why the affinity rather than the index is the honest parameter.
    #[must_use]
    pub const fn targets(&self, aff: u64) -> bool {
        if self.broadcast {
            // "All PEs excluding self." A guest may only broadcast within its own machine, which
            // costs nothing to enforce here: the caller only ever offers it vCPUs of the issuing
            // guest.
            return aff != self.sender;
        }
        // The named cluster must be this PE's. A guest that asks for a non-zero `Aff1`/`Aff2`/`Aff3`
        // names no vCPU baleen has, and gets an empty target set rather than a wrong one.
        if aff & !AFF0_MASK != self.cluster {
            return false;
        }
        let aff0 = aff & AFF0_MASK;
        // The target list covers `[range_base, range_base + 16)`. Outside that window the write says
        // nothing about this PE — it is not a denial, it is a different range, and a guest wanting
        // both must issue two writes. That is the architecture's design, not a simplification.
        if aff0 < self.range_base || aff0 >= self.range_base + TARGETS_PER_RANGE {
            return false;
        }
        self.list & (1 << (aff0 - self.range_base)) != 0
    }
}

// ⚠ There is deliberately NO `affinity_of` convenience wrapper here. One was written and deleted
// before this file was ever compiled: a second name for `vcpu_affinity` is a second derivation of
// the vCPU→affinity mapping, which is precisely the defect ⑱-3b-i spent a rung closing (two
// encodings in two crates, with a doc claiming there was one). Callers say `vcpu_affinity(v)`.
