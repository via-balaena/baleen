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
//! * `hv-metal` (from M3) — the thin, fenced `unsafe` core that plugs real VMX,
//!   page tables, and the APIC into the same traits.
//!
//! Because the seam is a set of traits, the same well-tested logic runs on your
//! laptop and on the metal, and the only thing hardware can falsify is this thin
//! translation layer.

#![no_std]

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
    /// Set the guest instruction pointer for the next entry.
    fn set_entry(&mut self, rip: u64);
}
