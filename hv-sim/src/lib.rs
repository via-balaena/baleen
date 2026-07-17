// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # hv-sim — the deterministic twin
//!
//! The host-side implementation of the [`hv_hal`] fence, and the [`scenario`]
//! runner that drives [`hv_core`] through thousands of seeded interleavings on a
//! laptop. Guest memory is a `Vec<u8>`; time is a counter you advance by hand; a
//! "VMEXIT" is a function call. This is the twin of the bare-metal target, and it
//! is where ~80% of development is meant to happen — no VM required.

use std::cell::Cell;

use hv_hal::{Gpa, GuestMemory, MemError, Ticks, TimeSource, VcpuOps};

/// Guest physical memory backed by a plain byte vector.
pub struct FakeMemory {
    bytes: Vec<u8>,
}

impl FakeMemory {
    /// Zeroed guest memory of `size` bytes.
    pub fn new(size: usize) -> Self {
        FakeMemory {
            bytes: vec![0; size],
        }
    }
}

impl GuestMemory for FakeMemory {
    fn read(&self, gpa: Gpa, buf: &mut [u8]) -> Result<(), MemError> {
        let start = gpa as usize;
        let end = start.checked_add(buf.len()).ok_or(MemError::OutOfBounds)?;
        let src = self.bytes.get(start..end).ok_or(MemError::OutOfBounds)?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn write(&mut self, gpa: Gpa, buf: &[u8]) -> Result<(), MemError> {
        let start = gpa as usize;
        let end = start.checked_add(buf.len()).ok_or(MemError::OutOfBounds)?;
        let dst = self
            .bytes
            .get_mut(start..end)
            .ok_or(MemError::OutOfBounds)?;
        dst.copy_from_slice(buf);
        Ok(())
    }
}

/// A clock the harness cranks by hand. Because *we* own the clock, the schedule of
/// events is entirely reproducible from a seed. `now` is behind a `Cell` so the
/// clock can be advanced while it is shared with the core by `&`.
pub struct ManualClock {
    now: Cell<Ticks>,
}

impl ManualClock {
    /// A clock reading zero.
    pub fn new() -> Self {
        ManualClock { now: Cell::new(0) }
    }

    /// Advance time by `by` ticks.
    pub fn advance(&self, by: Ticks) {
        self.now.set(self.now.get() + by);
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeSource for ManualClock {
    fn now(&self) -> Ticks {
        self.now.get()
    }
}

/// A [`VcpuOps`] that records what the core asked for instead of touching a CPU,
/// so tests can assert on the requests. Unused by M1's toy calls; here so the
/// harness already covers the whole fence.
#[derive(Debug, Default)]
pub struct RecordingVcpu {
    /// Interrupt vectors injected, in order.
    pub injected: Vec<u8>,
    /// The most recently requested entry point, if any.
    pub entry: Option<u64>,
}

impl VcpuOps for RecordingVcpu {
    fn inject_interrupt(&mut self, vector: u8) {
        self.injected.push(vector);
    }

    fn set_entry(&mut self, rip: u64) {
        self.entry = Some(rip);
    }
}

pub mod enumerate;
pub mod scenario;
