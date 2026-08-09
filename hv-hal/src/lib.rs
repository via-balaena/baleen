// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # hv-hal — the fence
//!
//! These traits are the entire surface `hv-core` is allowed to touch. The core
//! reaches memory, time, and CPUs only through here — never hardware directly.
//!
//! Exactly two implementations exist:
//!
//! * [`hv-sim`](../hv_sim/index.html) — a host implementation where guest memory is
//!   a `Vec<u8>` and time is a counter you advance by hand. This is what makes
//!   `cargo test` exercise the scheduler.
//! * `hv-metal` (from M3) — the thin, fenced `unsafe` core that plugs real hardware
//!   virtualization, page tables, and the interrupt controller into the same traits.
//!
//! Because the seam is a set of traits, the same well-tested logic runs on your
//! laptop and on the metal, and the only thing hardware can falsify is this thin
//! translation layer.
//!
//! **Architecture-neutral by design — ARM and x86 are co-equal targets.** These trait
//! signatures deliberately name no CPU architecture: `Gpa`/`Ticks` are plain integers,
//! memory is bytes, a vCPU takes an interrupt vector and an entry point. The *first*
//! `hv-metal` backend is AArch64 (the ARM virtualization extensions at EL2, Stage-2
//! translation, the GIC, the generic timer); an x86-64 backend (Intel VMX / EPT, the LAPIC,
//! the TSC) is an equally first-class goal and plugs in behind exactly these traits — the
//! portable brain above does not change. Keeping this surface free of any architecture-
//! specific concept (a VMCS field, an `ept_*` type, a GIC redistributor) is what keeps that
//! promise cheap, so it is a standing constraint on anything added here. Confirmed by
//! Architecture Audit #1 (`docs/AUDIT-1-HAL-FENCE.md`), which re-derived this surface against
//! the first real (ARM) backend and found it neutral.

// ⑳ — **`forbid`, not `deny`, and this crate has never needed `unsafe`.**
//
// The project's shape is "a verified core with a thin fenced `unsafe` layer in `hv-metal`". That
// was TRUE of every workspace crate and enforced by NOTHING: a `grep` said zero, and a convention
// is not a gate. `forbid` makes it a build error that no inner `allow` can override — which is the
// point, since the failure mode is somebody reaching for `unsafe` locally and silencing the lint
// beside it.
//
// ⚠ `hv-metal` is deliberately NOT given this: it is the fenced layer, it needs `unsafe` for MMIO
// and `asm!`, and its job is to keep that surface small and documented rather than absent.
#![forbid(unsafe_code)]
#![no_std]
// ㉔ — **every private item carries a doc.** Inserting an item between a doc comment and the item it
// documents silently re-parents the block, leaving the displaced item bare; that is valid Rust, and
// `git diff` shows it as clean added lines with no sign the lines above changed meaning. It happened
// twice in `xtask` in one day, the second time hours after the lesson was written. This crate was
// already at ONE warning, so enabling the lint LOCKS IN a property it effectively held rather than
// buying a new one. See `xtask/src/main.rs`'s block for the full account and the partial-guard
// caveat.
#![warn(clippy::missing_docs_in_private_items)]

/// Guest-physical address.
pub type Gpa = u64;

/// Opaque monotonic time, in hypervisor ticks. Its only guarantee is that it does
/// not run backwards; the *source* of the value is a [`TimeSource`], so the core
/// never assumes a real clock.
pub type Ticks = u64;

/// Failure accessing guest memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemError {
    /// The access fell outside the guest's physical address space.
    OutOfBounds,
}

/// Read/write access to a guest's physical memory.
pub trait GuestMemory {
    /// Fill `buf` from guest-physical address `gpa`.
    fn read(&self, gpa: Gpa, buf: &mut [u8]) -> Result<(), MemError>;
    /// Write `buf` to guest-physical address `gpa`.
    fn write(&mut self, gpa: Gpa, buf: &[u8]) -> Result<(), MemError>;
}

/// A monotonic clock. `hv-core` owns no clock of its own; determinism in the
/// simulator comes from the harness advancing this by hand, one tick at a time.
pub trait TimeSource {
    /// The current time.
    fn now(&self) -> Ticks;
}

/// Control over a single virtual CPU.
///
/// Unused by the M1 toy dispatcher, but defined now so the shape of the fence is
/// fixed before any hardware exists behind it.
pub trait VcpuOps {
    /// Queue an interrupt `vector` for delivery on the next guest entry.
    fn inject_interrupt(&mut self, vector: u8);
    /// Set the guest instruction pointer (the program counter) for the next entry. `entry` is an
    /// architecture-neutral name deliberately: on AArch64 it lands in `ELR_EL2` / the guest `PC`,
    /// on x86 in `RIP` — the trait names neither (Architecture Audit #1).
    fn set_entry(&mut self, entry: u64);
}
