// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Which guest is this index talking about? — roles, so a SLIP cannot compile
//!
//! ## The defect, MEASURED rather than imagined
//!
//! `switch_context` moves the pCPU from one guest to another, and it names them `cur` and `next`.
//! Both were `usize`, so **swapping them typechecks**, and it indexes per-guest state eighteen times.
//! Most swaps are loud — restore the wrong context and the guest dies on its first instruction; the
//! wrong `VTTBR_EL2` faults on the first fetch, which is ③-b2b-ii's documented probe.
//!
//! **Two of them are silent, and both were confirmed by running them through the gate:**
//!
//! | swap | gate result |
//! |---|---|
//! | `VGIC[next].is_enabled(VTIMER)` → `[cur]` | **passes, zero failures** |
//! | `flush_pending_to_lrs(next)` → `(cur)` | **passes, zero failures** |
//!
//! The first is the timer-mediation seam — the line that decides whether the *incoming* guest gets
//! its timer re-armed. It reads the wrong guest's distributor and nothing notices, because both
//! Alpine guests enable their timer and the two answers agree. That is design-lesson #127 one more
//! time: the safety was a property of the workload, not of the code.
//!
//! ## The fix: an index must say which ROLE the guest is playing
//!
//! [`Outgoing`], [`Incoming`] and [`Running`] are distinct types over the same slot number, and
//! **their inner value is private to this module** — which is why this is a module at all rather than
//! three newtypes beside the statics. From `linux.rs` there is no `.0`, no `as usize`, and no way to
//! reach the number except by handing the role to [`PerGuest`], which only accepts the matching one.
//! So inside a switch, `X.inc(cur)` is a type error and `X[cur]` does not exist.
//!
//! ## ★ THE CEILING, and it was found by running the probe rather than by reasoning
//!
//! **What is closed: changing the VARIABLE.** `X.inc(next)` → `X.inc(cur)` is
//! `expected Incoming, found Outgoing` — a hard build error, verified for both measured sites. That
//! is exactly the defect that was silent: a one-token slip.
//!
//! **What is NOT closed: changing the ACCESSOR and the variable together.** `X.inc(next)` →
//! `X.out(cur)` compiles, because it is internally consistent — `out` takes an `Outgoing` and `cur`
//! is one. **The first kill probe tried precisely that and BUILT CLEAN**, which is why this section
//! exists: the tidy claim "a swap cannot compile" is false, and only the narrower one is true.
//!
//! That is the same shape as ⑰-a's ceiling — a *forgotten* context component became impossible while
//! a *wrong* one still compiled. A coordinated two-token edit is a deliberate-looking change that a
//! reviewer sees; a one-token slip is the one that survives review, and it is the one now impossible.
//!
//! ## What this does NOT do
//!
//! [`PerGuest::at`] takes a plain slot, for the report and handler code where only one guest is in
//! play and there is no role to confuse. That is deliberate: the defect this closes is *two live
//! roles in one function*, and code with a single subject cannot have it. **A future switch-like
//! function must take roles, not slots** — the type is the reminder.
//!
//! Nor is this a proof. `hv-metal` is not a Kani target; what it is, is total over the code as
//! written, which is the same standard ⑰-a set for context components.

/// The guest that is leaving the pCPU.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Outgoing(usize);

/// The guest that is arriving on the pCPU.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Incoming(usize);

/// The guest that holds the pCPU once a switch has completed.
///
/// Deliberately minimal: it exists only so [`Incoming::now_running`] has somewhere to go, which is
/// what lets `CURRENT` be stored without the switch ever holding a bare slot. Handler code still
/// uses plain slots — a handler has ONE subject and so cannot confuse two roles, which is the defect
/// this module closes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Running(usize);

impl Outgoing {
    /// Name a slot as the outgoing guest. **The one place a raw slot becomes this role** — keeping it
    /// explicit is what makes the seam reviewable.
    pub(crate) const fn slot(s: usize) -> Self {
        Self(s)
    }
}

impl Incoming {
    /// Name a slot as the incoming guest.
    pub(crate) const fn slot(s: usize) -> Self {
        Self(s)
    }
    /// Becomes the running guest once the switch has completed — the ONLY transition between roles,
    /// and it exists because step 7 of a switch is exactly "the incoming guest is now the running
    /// one". Anything else would be a role laundering itself.
    pub(crate) const fn now_running(self) -> Running {
        Running(self.0)
    }
}

impl Running {
    /// The raw slot, for the handful of callers that must index something this module does not own
    /// (the console's per-guest line buffers, `slot_dom`). Only [`Running`] has this, because a
    /// handler has ONE subject and so cannot confuse two roles — which is the whole defect.
    pub(crate) const fn index(self) -> usize {
        self.0
    }
}

/// Per-guest state that can only be reached by naming the role of the guest you mean.
pub(crate) struct PerGuest<T, const N: usize>([T; N]);

impl<T, const N: usize> PerGuest<T, N> {
    pub(crate) const fn new(inner: [T; N]) -> Self {
        Self(inner)
    }

    /// The **outgoing** guest's element.
    pub(crate) fn out(&self, g: Outgoing) -> &T {
        &self.0[g.0]
    }

    /// The **incoming** guest's element.
    pub(crate) fn inc(&self, g: Incoming) -> &T {
        &self.0[g.0]
    }

    /// An arbitrary slot — for report and setup code, where there is no role to confuse. See the
    /// module docs for why this is not the hole it looks like.
    pub(crate) fn at(&self, slot: usize) -> &T {
        &self.0[slot]
    }

    /// The **outgoing** guest's element, mutably.
    pub(crate) fn out_mut(&mut self, g: Outgoing) -> &mut T {
        &mut self.0[g.0]
    }

    /// The **incoming** guest's element, mutably.
    pub(crate) fn inc_mut(&mut self, g: Incoming) -> &mut T {
        &mut self.0[g.0]
    }

    /// An arbitrary slot, mutably — setup code only.
    pub(crate) fn at_mut(&mut self, slot: usize) -> &mut T {
        &mut self.0[slot]
    }
}
