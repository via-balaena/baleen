// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # EL2 configuration — claim the hypervisor level for AArch64 operation (Arc 3)
//!
//! Arc 2 confirmed we run at EL2 and made a fault diagnosable. Arc 3 takes the first *configuring*
//! step: set `HCR_EL2` for AArch64 EL2 operation. Deliberately minimal — this arc has **no guest**
//! (the first EL1 guest is M4), so it sets only the one field that declares the execution state of
//! the lower EL, and nothing else.
//!
//! ## Contract
//!
//! - **Property:** after [`configure`], `HCR_EL2.RW` (bit 31) is 1 — any exception taken *from*, or
//!   `ERET` *to*, EL1 uses AArch64 state — and every other `HCR_EL2` field is 0 (stage-2 off,
//!   no exception routing, no traps). A full-register write, not a read-modify-write, because the
//!   architecture leaves `HCR_EL2`'s reset value UNKNOWN; writing the whole value also pins
//!   `E2H` (bit 34) to 0, without which `RW` would not carry its plain non-VHE meaning.
//! - **Check:** [`configure`] reads `HCR_EL2` back and returns it; `rust_main` asserts bit 31 is set
//!   and prints the value, and the CI boot-test matches the `HCR_EL2.RW=1` marker — so a regression
//!   that silently dropped the write is caught on every boot.
//! - **Scope:** *plumbing / refines* — EL2 configuration, **no isolation content**. Setting `RW=1`
//!   is configuration only until we actually drop to EL1: with no guest, nothing yet executes at the
//!   lower EL. The guest-facing `HCR_EL2` bits — `VM` (stage-2), `TGE`, `IMO`/`FMO`/`AMO` (interrupt
//!   routing), and the trap group (`TSC`, `TWI`/`TWE`, `TVM`, …) — are deliberately left 0 and land
//!   in M4 when there is a guest to trap. Building them now would be pre-building M4's isolation
//!   surface, exactly the "don't skip ahead" the roadmap forbids.
//!
//! ## Provenance
//!
//! The `HCR_EL2` field layout (`RW` = bit 31, `E2H` = bit 34, `VM` = bit 0, `TGE` = bit 27, the
//! trap-bit group) and the "reset is UNKNOWN, initialize explicitly" rule are from the **Arm
//! Architecture Reference Manual (Arm ARM), section D1 / the `HCR_EL2` register description** — a
//! published architecture spec, re-derived independently by a spec-blind auditor and converged with
//! this code (three-way with the running emulator; design-lesson #24).
//!
//! ## Unsafe
//!
//! The `unsafe` is a single `msr`/`mrs` pair on `HCR_EL2`, EL2-legal, with an `isb` so the new value
//! is context-synchronized before we trust it. No memory effect beyond the named register.

use core::arch::asm;

/// `HCR_EL2.RW` — bit 31. `1` = the next-lower EL (EL1) executes in AArch64 state.
const HCR_EL2_RW: u64 = 1 << 31;

/// Configure `HCR_EL2` for minimal AArch64 EL2 operation and return the value read back.
///
/// Writes the whole register (`RW=1`, all else 0) rather than setting a bit into an UNKNOWN reset
/// value, then `isb` so the write is in effect before the read-back — and before any later `ERET`
/// to EL1 (though `ERET` is itself context-synchronizing, so a guest would see the new value
/// regardless). Returns the post-write `HCR_EL2` so the caller can confirm the field took.
pub(crate) fn configure() -> u64 {
    let readback: u64;
    // SAFETY: `HCR_EL2` is RW at EL2; the full-register write sets exactly RW and clears the rest
    // (including E2H, so RW keeps its non-VHE meaning). `isb` context-synchronizes the write before
    // the read-back. No memory is touched.
    unsafe {
        asm!(
            "msr hcr_el2, {v}",
            "isb",
            "mrs {r}, hcr_el2",
            v = in(reg) HCR_EL2_RW,
            r = out(reg) readback,
            options(nomem, nostack, preserves_flags),
        );
    }
    readback
}

/// Whether `HCR_EL2.RW` is set in a read-back value — the post-condition [`configure`] establishes.
///
/// Checks the single bit rather than exact-equality with `HCR_EL2_RW`, so an implementation that
/// reads back an IMPDEF/RES1 bit elsewhere in the register does not spuriously fail the confirm; the
/// property Arc 3 asserts is precisely "RW is 1", nothing more.
pub(crate) fn rw_is_aarch64(hcr: u64) -> bool {
    hcr & HCR_EL2_RW != 0
}
