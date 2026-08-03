// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

#![no_std]
//! # The guest's device models, under the fence (⑯)
//!
//! ## The gap this crate exists to close
//!
//! Arc ③ took every real device away from the real-Linux guest: the console (③-a1), interrupt
//! delivery (③-a2), the interrupt controller (③-b1). By the end of it `stage2::windows().device_len
//! == 0` — a compile-time fact — and the guest reached no hardware MMIO at all.
//!
//! That is a real isolation result, and it had a cost nobody had written down. **Before ③ the guest
//! touched real hardware and Stage-2 mediated it — the proven artifact**, with an ∀-frame refinement
//! and an ∀-address walk behind it. **After ③ the guest touched `vgic.rs` and `vpl011.rs`**: pure
//! EL2 code, no `unsafe` anywhere in it, and no machine-checked property of any kind. The guest's
//! entire device-facing surface had moved *out* of a proven artifact and into an unproven one, and
//! the only thing checking it was a boot witness.
//!
//! A boot witness can only see what a boot exercises. The shipped Alpine kernel touches the emulated
//! GIC exactly 410 times across a small, regular set of registers — it is not an adversary, and it
//! never offers an offset the model did not expect. **The guest chooses the offset**, and the decode
//! turns that offset into an array index. Nothing about "an unmodified kernel boots" says what
//! happens at the offsets that kernel happens not to use.
//!
//! ## The move, and this project has made it once already
//!
//! This is exactly what `hv-s2` is, one layer out. `hv-metal`'s `stage2.rs` says it of itself: the
//! refinement *"has moved OUT of this crate into `hv_s2`, a pure `no_std` library under the
//! `unsafe_code = "forbid"` fence… It is therefore host-testable, fuzzable, enumerable, and
//! **provable**, where before it could only be argued."* `hv-metal` is workspace-EXCLUDED — it
//! cannot link for the host — so `hv-verify` cannot depend on it and code living there is
//! *structurally* unreachable by Kani. Moving a model here is what makes a theorem about it
//! possible to state at all.
//!
//! ## What belongs here, and what deliberately does not
//!
//! **Here: the model.** The register file, its decode, its reset values, and the state a driver can
//! observe. Nothing else.
//!
//! **⑰-b′ widened that sentence, and the widening is worth naming rather than absorbing.**
//! [`vgic_cpuif`] is not a register file a guest DRIVES — it is the GICv3 **CPU interface**, the
//! `ICH_LR<n>_EL2` bank that **EL2 writes** to present a virtual interrupt, plus the transform a vCPU
//! switch applies to a saved copy of it. A guest never addresses it. It belongs here anyway because
//! the criterion that actually earns a module a place in this crate is not "the guest touches it" but
//! **"it is a pure function of ordinary state, so a theorem about it is statable"** — and the
//! distributor half was only ever the first thing to satisfy that. The two halves are one device seen
//! from its two sides: [`gicv3`] is what the guest reads, [`vgic_cpuif`] is what EL2 writes, and an
//! interrupt is not delivered until both agree.
//!
//! **Not here: the deployment.** Three kinds of thing stay in `hv-metal`, and the split is the part
//! worth getting right:
//!
//! 1. **The claims about *this* machine.** `stage2::windows().device_len == 0`, `VPL011_BASE ==
//!    UART0_BASE`, `VTIMER_INTID < NUM_INTIDS`. These are `const assert!`s binding a model to a
//!    board; they are the metal's statements, and they lose their meaning here.
//! 2. **The hardware pokes.** Relaying a transmitted byte to the real UART, mirroring a timer enable
//!    onto the physical redistributor. Those are `unsafe` MMIO, which this crate forbids — and
//!    keeping them at the call site is what lets the model be pure in the first place.
//! 3. **The boot witnesses.** Trap counters, byte tallies, the marker matcher. See below: this one
//!    is a change from how the models were written, and it is deliberate.
//!
//! ## Why the witness counters did NOT come along
//!
//! In `hv-metal` both models carried their own witness state — `traps`, `enables`, `dr_writes`,
//! `saw_needle` — incremented inside `mmio_read`/`mmio_write`. That is why `mmio_read` took `&mut
//! self`: **a read mutated the device.**
//!
//! It made the model's most load-bearing theorem unstateable. `handle_vgic_access` **parks** the
//! machine when a write returns `Err`, on the reasoning that an unmodelled register must not be
//! half-applied — "report and park, never guess". The theorem that justifies parking is *`Err` ⇒ the
//! state is bit-identical to before*. With a trap counter inside the struct that is simply **false**,
//! and the best available statement becomes "identical except these fields" — which forces a reader
//! to trust a hand-drawn partition of the struct into semantic and non-semantic halves. This
//! repository spends whole rungs deleting exactly that kind of prose glue.
//!
//! So the counters stayed in `hv-metal`, where the boot witness they serve is reported from. The
//! model here holds **only** state a guest driver could observe, `mmio_read` takes `&self`, and the
//! fail-closed theorem quantifies over the whole struct with no exception clause.
//!
//! ## Where this crate actually stands — read before believing the word "provable"
//!
//! ⑯ is complete: the models moved here (steps 1 and 2) and **`hv-verify::device_models` now carries
//! fourteen harnesses over them** (step 3). Both entry points of both models are proven total over
//! every offset, width and value a guest can name; the GIC's decode is proven a partition and its
//! failed writes proven to change nothing; the enable state a caller mediates on is proven to move
//! only where an enable register names it.
//!
//! **Keep this paragraph honest as things change.** It is the one place a reader is told what the
//! fence does and does not buy, and it has gone stale twice already — once saying the GIC model was
//! "a later step" in the very commit that moved it, once claiming no harnesses existed in the commit
//! that added them.
//!
//! ## The honest ceiling — and it is the important half
//!
//! **This crate makes STRUCTURE provable, not CONFORMANCE.** A model that decodes every offset
//! perfectly, never panics, never aliases two banks — and returns architecturally wrong *values* —
//! satisfies every property `hv-verify` states about it. Conformance is not a theorem here and
//! should not be: the check that these registers mean what a GICv3 or a PL011 means is an unmodified
//! Linux kernel booting on them, which is what the `real-linux boot (QEMU)` gate runs.
//!
//! The two are complementary and neither substitutes for the other. The boot proves the model is
//! *right* on the paths a kernel walks; the proofs cover every path it does not.
//!
//! ## Unsafe
//!
//! **Forbidden**, by the workspace lint. These are register files over ordinary memory: no MMIO, no
//! system registers, no hardware. Every place the emulation meets the machine is a call site in
//! `hv-metal`, where the rest of the `unsafe` already lives.

pub mod gicv3;
pub mod pending;
pub mod pl011;
pub mod vgic_cpuif;
