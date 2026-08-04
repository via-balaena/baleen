// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Which guest — and which of its vCPUs — is this index talking about?
//!
//! ## The defect this started from, MEASURED rather than imagined
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
//! [`Outgoing`], [`Incoming`] and [`Running`] are distinct types, and **their inner values are
//! private to this module** — which is why this is a module at all rather than three newtypes beside
//! the statics. From `linux.rs` there is no `.0`, no `as usize`, and no way to reach the numbers
//! except by handing the role to a container, which only accepts the matching one. So inside a
//! switch, `X.inc(cur)` is a type error and `X[cur]` does not exist.
//!
//! ## ★ ⑱-3a — A ROLE NAMES A vCPU, NOT A GUEST, AND SOME STATE IS PER-vCPU
//!
//! ⑱ gives a guest more than one vCPU. That splits the metal's per-guest state in two, and **the
//! division is not a matter of taste**: a guest's vCPUs share one address space, one emulated UART
//! and one distributor, and are retired together — but they must *not* share their register context
//! or their pending interrupts.
//!
//! **The finding that motivated this rung.** The synthetic path has kept a **per-vCPU** pending set
//! since III-1 (`guest.rs`'s `VCPU_PENDING`), whose own reasoning is that a shared one "would reopen
//! the cross-vCPU leak 8b/III-3 closed". The real-Linux path's `LINUX_PENDING` was **per-guest**. At
//! one vCPU per guest the two axes coincide numerically — 2 guests × 1 vCPU, 1 domain × 2 vCPUs — so
//! nothing has ever noticed. At two, both of a guest's vCPUs would share one pending set and vCPU 0
//! would drain vCPU 1's SGIs into its own list registers: **an interrupt delivered to the wrong vCPU
//! of the same guest, which is not a crash, not a fault, and not a marker.**
//!
//! ### What is STRUCTURAL, and it is the point of the rung
//!
//! [`PerGuest`] requires its element to be [`PerGuestState`]; [`PerVcpu`] requires [`PerVcpuState`].
//! `VcpuCtx` and `PendingSet` declare only the latter, so
//!
//! ```ignore
//! static LINUX_PENDING: PerGuest<PendingSet, NUM_GUESTS> = ...;   // does not compile
//! ```
//!
//! **A `PerVcpu` type on its own would have bought nothing** — `PerGuest::inc(next)` compiles
//! perfectly well against a shared pending set, which is exactly how the bug would have shipped. The
//! trait is what makes the classification the compiler's business. The converse holds too:
//! `DeployedGic` declares only [`PerGuestState`], so a per-vCPU distributor does not compile either.
//!
//! ### What is CONVENTION, declared rather than implied
//!
//! **The thirteen witness counters are `AtomicU64`, and that type legitimately lives on both axes** —
//! a per-guest tally and a per-vCPU tally are both meaningful. So `AtomicU64` implements both traits
//! and the compiler has nothing to say about it. Newtyping each counter would buy a check on state
//! where a mistake is a wrong number in a report, not an isolation defect. **Structural where a
//! mistake is silent and isolation-relevant; documented where it is loud and cosmetic.**
//!
//! ## ★ THE CEILING, and it was found by running the probe rather than by reasoning
//!
//! **What is closed: changing the VARIABLE.** `X.inc(next)` → `X.inc(cur)` is
//! `expected Incoming, found Outgoing` — a hard build error, verified for both measured sites. That
//! is exactly the defect that was silent: a one-token slip. **⑱-3a adds a second closed case:**
//! *omitting the vCPU axis* from a per-vCPU state is now a build error too.
//!
//! **What is NOT closed: changing the ACCESSOR and the variable together.** `X.inc(next)` →
//! `X.out(cur)` compiles, because it is internally consistent — `out` takes an `Outgoing` and `cur`
//! is one. **The first kill probe tried precisely that and BUILT CLEAN**, which is why this section
//! exists: the tidy claim "a swap cannot compile" is false, and only the narrower one is true. ⑱-3a
//! does not change that, and does not make a *wrong* vCPU index a build error either — only a
//! *missing* axis. Same shape as ⑰-a: forgotten → impossible, wrong → still compiles.
//!
//! ## What this does NOT do
//!
//! [`PerGuest::at`] takes a plain slot, for the report and handler code where only one guest is in
//! play and there is no role to confuse. That is deliberate: the defect this closes is *two live
//! roles in one function*, and code with a single subject cannot have it. **A future switch-like
//! function must take roles, not slots** — the type is the reminder.
//!
//! **Two accessors this rung would naturally have are ABSENT on purpose** — `Running::vcpu` and
//! `PerGuest::out_mut`. Nothing calls them, and shipping API on the strength of "⑱-3b will want it"
//! is design-lesson #148, which this module already applied once. Each is a one-line addition when a
//! caller exists. (The `vcpu` field is still read — by [`Running::pack`] — so the axis is carried,
//! just not yet projected out of a `Running`.)
//!
//! ⚠ **A third, `PerVcpu::out`, was trimmed and had to be PUT BACK — read why.** It looked dead in a
//! `--features real-linux` build, and it is: its four callers are all in the tick-deferral
//! **selftest** probe. A single-config build is not evidence about a crate with five of them, which
//! is what `cargo xtask metal-lint` exists for; trimming on that warning broke the `real-linux,
//! selftest` config and the boot gate caught it. It is now `#[cfg(feature = "selftest")]`, which
//! names the configuration it belongs to (⑭'s rule) rather than hiding the question.
//!
//! Nor is this a proof. `hv-metal` is not a Kani target; what it is, is total over the code as
//! written, which is the same standard ⑰-a set for context components.

/// **How many vCPUs each guest has**, and the one place that number is stated.
///
/// ⑱-2 made the emulated GIC take it as a parameter and ⑱-3a makes the metal's per-vCPU state take
/// it too, so it lives here — with the types that name the axis — rather than in either consumer.
/// `vgic.rs` reads it, and its `const assert!` that the redistributor region can hold that many
/// frames is what keeps this constant honest.
///
/// **Still 1.** Raising it is ⑱-3b, which needs a scheduler that can pick a vCPU and a `PSCI CPU_ON`
/// that can start one; raising it alone would give every guest a vCPU nothing ever runs.
pub(crate) const VCPUS_PER_GUEST: usize = 1;

/// The vCPU a guest boots on, and — until ⑱-3b — the only one that runs.
pub(crate) const BOOT_VCPU: usize = 0;

const _: () = assert!(
    BOOT_VCPU < VCPUS_PER_GUEST,
    "the boot vCPU must be one the guest actually has"
);

/// The vCPU that is leaving the pCPU.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Outgoing {
    guest: usize,
    vcpu: usize,
}

/// The vCPU that is arriving on the pCPU.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Incoming {
    guest: usize,
    vcpu: usize,
}

/// The vCPU that holds the pCPU once a switch has completed.
///
/// Deliberately minimal: it exists only so [`Incoming::now_running`] has somewhere to go, which is
/// what lets `CURRENT` be stored without the switch ever holding a bare index.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Running {
    guest: usize,
    vcpu: usize,
}

impl Outgoing {
    /// Name a guest's vCPU as the outgoing one. **The one place raw indices become this role** —
    /// keeping it explicit is what makes the seam reviewable.
    pub(crate) const fn at(guest: usize, vcpu: usize) -> Self {
        Self { guest, vcpu }
    }
}

impl Incoming {
    /// Name a guest's vCPU as the incoming one.
    pub(crate) const fn at(guest: usize, vcpu: usize) -> Self {
        Self { guest, vcpu }
    }
    /// Becomes the running vCPU once the switch has completed — the ONLY transition between roles,
    /// and it exists because the last step of a switch is exactly "the incoming vCPU is now the
    /// running one". Anything else would be a role laundering itself.
    pub(crate) const fn now_running(self) -> Running {
        Running {
            guest: self.guest,
            vcpu: self.vcpu,
        }
    }
}

impl Running {
    /// The vCPU a guest is entered on at boot — the initial value of `CURRENT`. A `const fn` so the
    /// static can be initialised from the same packing every later store uses, rather than from a
    /// literal that would have to be kept in step with it.
    pub(crate) const fn at_boot(guest: usize) -> Self {
        Self {
            guest,
            vcpu: BOOT_VCPU,
        }
    }

    /// The guest this vCPU belongs to, for the handful of callers that must index something this
    /// module does not own (the console's per-guest line buffers, `slot_dom`). Only [`Running`] has
    /// this, because a handler has ONE subject and so cannot confuse two roles.
    pub(crate) const fn guest(self) -> usize {
        self.guest
    }

    /// Fold the pair into the single word `CURRENT` stores, and back. **The packing is here, once**,
    /// because a second encoding of "which vCPU is running" is the defect ⑭ spent a rung removing —
    /// and because keeping it inside the module is what stops `linux.rs` reconstructing a role from
    /// arithmetic of its own.
    pub(crate) const fn pack(self) -> usize {
        self.guest * VCPUS_PER_GUEST + self.vcpu
    }

    /// Inverse of [`Running::pack`].
    ///
    /// **The `expect` is a tripwire, not a suppression.** With `VCPUS_PER_GUEST == 1` the modulo is
    /// trivially zero and clippy is right to say so — but the expression is the correct general
    /// formula, and `expect` (unlike `allow`) FAILS THE BUILD once the lint stops firing. So the day
    /// ⑱-3b raises the count, this line reports itself as no longer needing the exemption rather
    /// than sitting there as a stale annotation nobody re-reads.
    #[expect(
        clippy::modulo_one,
        reason = "degenerate only while VCPUS_PER_GUEST == 1"
    )]
    pub(crate) const fn unpack(packed: usize) -> Self {
        Self {
            guest: packed / VCPUS_PER_GUEST,
            vcpu: packed % VCPUS_PER_GUEST,
        }
    }
}

/// **State a whole guest owns**, shared by every one of its vCPUs — its address space, its emulated
/// devices, whether it has been retired.
///
/// Implementing this is a claim, and the compiler holds you to it: a type that declares only
/// [`PerVcpuState`] cannot be put in a [`PerGuest`].
pub(crate) trait PerGuestState {}

/// **State one vCPU owns.** Sharing it between a guest's vCPUs is an isolation defect *inside* a
/// guest — see the module docs on `LINUX_PENDING`, which is why this trait exists.
pub(crate) trait PerVcpuState {}

/// A witness tally is meaningful per guest *and* per vCPU, so it declares both and the compiler has
/// nothing to say about which axis a counter belongs on. Declared, not implied — see the module
/// docs' "what is convention" section.
impl PerGuestState for core::sync::atomic::AtomicU64 {}
impl PerVcpuState for core::sync::atomic::AtomicU64 {}

/// Per-guest state that can only be reached by naming the role of the vCPU you mean.
pub(crate) struct PerGuest<T: PerGuestState, const N: usize>([T; N]);

impl<T: PerGuestState, const N: usize> PerGuest<T, N> {
    pub(crate) const fn new(inner: [T; N]) -> Self {
        Self(inner)
    }

    /// The **outgoing** vCPU's guest's element.
    pub(crate) fn out(&self, g: Outgoing) -> &T {
        &self.0[g.guest]
    }

    /// The **incoming** vCPU's guest's element.
    pub(crate) fn inc(&self, g: Incoming) -> &T {
        &self.0[g.guest]
    }

    /// An arbitrary guest — for report and setup code, where there is no role to confuse. See the
    /// module docs for why this is not the hole it looks like.
    pub(crate) fn at(&self, guest: usize) -> &T {
        &self.0[guest]
    }

    /// The **incoming** vCPU's guest's element, mutably.
    pub(crate) fn inc_mut(&mut self, g: Incoming) -> &mut T {
        &mut self.0[g.guest]
    }

    /// An arbitrary guest, mutably — setup code only.
    pub(crate) fn at_mut(&mut self, guest: usize) -> &mut T {
        &mut self.0[guest]
    }
}

/// Per-**vCPU** state, indexed by both axes at once.
///
/// Nested arrays rather than one flat `[T; G * V]`, because const-generic arithmetic in an array
/// length is not stable — and because `[[T; V]; G]` makes the two axes visible in the type instead
/// of hidden in a multiplication.
pub(crate) struct PerVcpu<T: PerVcpuState, const G: usize, const V: usize>([[T; V]; G]);

impl<T: PerVcpuState, const G: usize, const V: usize> PerVcpu<T, G, V> {
    pub(crate) const fn new(inner: [[T; V]; G]) -> Self {
        Self(inner)
    }

    /// The **outgoing** vCPU's element.
    ///
    /// `cfg`-gated: its only callers today are the tick-deferral selftest probe's, so in a plain
    /// `real-linux` build it is genuinely dead. ⑭'s rule — name the configuration an item belongs
    /// to, rather than `allow(dead_code)` over every configuration at once.
    #[cfg(feature = "selftest")]
    pub(crate) fn out(&self, g: Outgoing) -> &T {
        &self.0[g.guest][g.vcpu]
    }

    /// The **incoming** vCPU's element.
    pub(crate) fn inc(&self, g: Incoming) -> &T {
        &self.0[g.guest][g.vcpu]
    }

    /// An arbitrary vCPU — for report and setup code, where there is no role to confuse.
    pub(crate) fn at(&self, guest: usize, vcpu: usize) -> &T {
        &self.0[guest][vcpu]
    }

    /// The **outgoing** vCPU's element, mutably.
    pub(crate) fn out_mut(&mut self, g: Outgoing) -> &mut T {
        &mut self.0[g.guest][g.vcpu]
    }

    /// The **incoming** vCPU's element, mutably.
    pub(crate) fn inc_mut(&mut self, g: Incoming) -> &mut T {
        &mut self.0[g.guest][g.vcpu]
    }

    /// An arbitrary vCPU, mutably — setup code only.
    pub(crate) fn at_mut(&mut self, guest: usize, vcpu: usize) -> &mut T {
        &mut self.0[guest][vcpu]
    }
}
