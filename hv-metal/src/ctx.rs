// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # What a vCPU context component IS, and why forgetting one is a compile error (⑰-a)
//!
//! ## The defect this closes, stated as history because that is the argument
//!
//! A vCPU context is a handful of components — the GPR array, the EL1 system registers, the vGIC
//! bank, the FP register file — and each must be **saved** and **restored**, and every one that
//! lives in hardware must also be **clobbered** by the switch that poisons. (The GPR array is the
//! exception on both counts: it moves between the context and the exception frame rather than the
//! CPU, and is not poisoned. It is still named in every traversal — see below.) Until this module
//! those were three lists maintained by hand in three places, with nothing tying them together.
//!
//! That is precisely how `v0..v31` stayed unsaved from M5 Arc 1 to ③-b2b-ii-f: not carelessness, a
//! structurally unenforced list. And `crate::vcpu`'s own `ctx_regs!` macro exists to prevent
//! exactly this defect *one layer down*, in its own words — *"there is no second list to drift from
//! the first … the compiler, not a reviewer, is what notices if an accessor forgets it"*. The layer
//! above it had the very defect the macro was written for.
//!
//! ## The observation that makes the fix cheap
//!
//! **Construction is already total.** `VcpuCtx::new()` is a struct literal, and Rust rejects a
//! struct literal that omits a field — so adding a component already breaks construction. It was
//! only the three *traversals* that ignored new fields silently. So the fix is not a new mechanism:
//! it is to make traversal obey the rule the language already enforces for construction.
//!
//! ## How, and it is one line per traversal
//!
//! Each of `save`/`restore`/`poison` opens by destructuring `Self` **with no `..`**:
//!
//! ```ignore
//! let Self { x: gprs, regs, vgic, fp } = self;
//! ```
//!
//! Add a field and every traversal fails to compile with **E0027, "pattern does not mention field
//! `…`"** — verified against the compiler before this module was written, rather than assumed. Bind
//! a field and fail to *use* it and you get `unused_variables`, which `cargo xtask metal-lint` runs
//! as `-D warnings`.
//!
//! **The two halves of the mistake are caught at different strengths, and the difference matters.**
//! "Forgot the field" is a hard **build** error — `cargo build` refuses it, so no path reaches a
//! running guest. "Named it but did not act on it" is only a **lint-gate** error: `cargo build`
//! emits a warning and produces a working binary, and it is `metal-lint` (a required CI job) that
//! turns it into a failure. Both are caught before merge; only the first is caught by a bare build.
//!
//! ## Why `poison` takes a receiver it never reads
//!
//! `CtxPoison::poison` clobbers live hardware and needs nothing from `&self`. It takes one anyway,
//! as a **type witness**, and that is the load-bearing part of the design rather than an oversight:
//! an associated `poison()` cannot be driven from a destructuring, so a forgotten component would
//! degrade from a hard error to an unused binding. Taking a receiver makes poisoning a *use* of the
//! binding, which puts `poison` under the same E0027 obligation as the other two traversals.
//!
//! ## The probes — RUN, not asserted, and one of them nearly passed for the wrong reason
//!
//! | probe | result |
//! |---|---|
//! | drop `fp` from `restore`'s pattern | **E0027** + E0425 — hard build error |
//! | add a field and forget it everywhere | **four** errors: E0063 at `new()` plus **one E0027 per traversal** |
//! | the historical bug: `fp` bound but never restored | **`error: unused variable: fp`** under `metal-lint` |
//!
//! The third is the one that matters, because it reconstructs the exact defect ③-b2b-ii-f fixed and
//! asks whether this rung would have caught it. It would.
//!
//! ⚠ **But it is a LINT-gate error, not a build error, and the difference nearly went unnoticed.**
//! The first attempt at that probe reported `metal-lint` failing and looked like a pass. It was not:
//! the scripted deletion had left a stray blank line, `metal-lint` runs `cargo fmt --check` **first
//! and exits on failure**, and clippy never ran at all. The probe was measuring formatting. Only
//! after normalizing the file did the real `unused variable` error appear. **Any probe against this
//! gate must leave the tree rustfmt-clean or it tests nothing** — a probe that silently no-ops looks
//! exactly like one that passed (design-lesson #111), and here it looked like one that *failed*,
//! which is worse: a false green would have been noticed, a false red was almost believed.
//!
//! ## What this does NOT do — the ceiling, stated here rather than discovered later
//!
//! It makes a **forgotten** component impossible. It does nothing about a **wrong** one: a `save`
//! that reads the wrong system register compiles perfectly, and a component whose `restore` is a
//! no-op is caught only by the runtime read-backs `crate::linux` already carries. Proving the
//! switch's *content* rather than its *coverage* needs the model extraction ⑰-b is for.
//!
//! Nor is `hv-metal` a Kani target; this is a property the compiler enforces, not one a proof
//! discharges. That is a real distinction and worth keeping: it is total over the code as written,
//! and says nothing about the code being right.

/// One component of a vCPU context — a piece of CPU state that a switch must carry.
///
/// Implemented by every field of a context struct that lives in **hardware** rather than in the
/// exception frame. The GPR array is deliberately not a member: see `crate::vcpu::VcpuCtx::save`
/// for why a whole-array assignment needs no help from this trait, and why it is still named in
/// every destructuring.
pub(crate) trait CtxComponent {
    /// Capture this component from the live CPU into the context.
    fn save(&mut self);

    /// Write this component from the context back onto the live CPU.
    ///
    /// # Safety
    /// The caller must be at EL2 with the outgoing context already saved, and this context must
    /// belong to the vCPU about to be resumed.
    unsafe fn restore(&self);
}

/// A component that the poisoning switch can clobber (⑰-a).
///
/// **Separate from [`CtxComponent`] because only one switch poisons.** The real-Linux path needs a
/// destructive step to make a switch-to-self non-vacuous; the synthetic path's cross-vCPU witness is
/// guest-OBSERVED (Phase III-3) and does not. Splitting the obligation keeps the default build —
/// which must stay byte-for-byte unchanged — free of a method it would never call.
#[cfg(feature = "real-linux")]
pub(crate) trait CtxPoison {
    /// Clobber this component's live hardware state.
    ///
    /// `&self` is a **type witness only** and is never read — see this module's docs for why that
    /// is what makes a forgotten component a compile error rather than an unused binding.
    ///
    /// # Safety
    /// The caller must be at EL2 with the outgoing context saved, and must restore before returning
    /// to EL1. Between this call and that restore the component's hardware state is garbage.
    unsafe fn poison(&self);
}
