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
//! ⚠ **⑱-3b-i re-examined that call. It stands, but the reasoning has a SECOND half that was
//! missing — and that half is not cosmetic.** `linux.rs`'s `TIMER_FORWARDED` says of itself: *"Per
//! guest since ③-b2b-ii-a. A merged count would stay green with one guest's forwarding path entirely
//! dead."* **At two vCPUs the per-guest counter IS the merged count**, one axis down: a guest whose
//! vCPU 1 handoff is entirely dead contributes `released = 0, deactivated = 0` to each of its own
//! handovers, which balances, so `report_timer_handoff` stays green with half the new tenant broken.
//!
//! So the counters' *storage axis* is wrong for ⑱ even though the invariants stored in them survive
//! (that derivation is on `report_timer_handoff`). **DECLARED, NOT CLOSED HERE, deliberately:** at
//! `VCPUS_PER_GUEST == 1` a `PerVcpu<AtomicU64, G, 1>` is `[[T; 1]; G]`, isomorphic to the `[T; G]`
//! it would replace — behaviour-nil *and* witness-nil, with no build error either, precisely because
//! `AtomicU64` implements both traits by the convention above. Moving fifteen counters for zero
//! evidence is not a change this project makes. It becomes checkable the moment a second vCPU
//! produces counts, which is ⑱-4.
//!
//! ## ★ ⑱-3b-i — AND A CALL SITE CAN DROP AN AXIS THE DECLARATION GOT RIGHT
//!
//! ⑱-3a closed the vCPU axis on **declarations**. Six call sites projected it away and re-supplied a
//! constant, which no container type can see. That is [`VcpuIdx`], where all six are tabulated with
//! what each does at two vCPUs — a guest that stops ticking, an EL2 livelock, interrupts delivered
//! to the wrong vCPU of the same guest, and a kernel panic on an MPIDR its device tree does not
//! describe. **Not one of them is loud**, which is the whole reason the rung is a type and not a
//! patch.
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
//! **Two accessors this module would naturally have are ABSENT on purpose** — `PerGuest::out_mut`
//! and `Outgoing::vcpu`. Nothing calls either, and shipping API on the strength of "a later rung
//! will want it" is design-lesson #148. Each is a one-line addition when a caller exists.
//!
//! ⚠ **⑱-3b-i also DELETED one — `PerVcpu::at` — and the deletion is worth a line.** It was the
//! plain-index accessor for "report and setup code", and its only two callers were
//! `at(current_slot(), BOOT_VCPU)`: precisely the defect below, wearing the escape hatch's clothes.
//! Replacing them with [`PerVcpu::of`] left it with no callers at all, in any of the five
//! `metal-lint` configurations — checked across all five rather than trimmed on the warning from
//! one, which is the mistake ⑱-3a made here and design-lesson #168 records.
//!
//! ⚠ **[`Running::vcpu`] was on that list and is now PRESENT — ⑱-3b-i found its callers, and there
//! were six.** Worth recording, because #148 is easy to read as "withhold and forget": the accessor
//! was withheld correctly (nothing called it), and the rung that needed it was the very next one.
//! What #148 buys is that the API arrives with its callers, so the shape is decided by them rather
//! than guessed a rung early — and the shape did change. The natural guess was `Running::vcpu`
//! alone; what the call sites actually wanted was [`PerVcpu::of`], which takes the *whole* role, so
//! that projecting the guest axis out and forgetting the vCPU axis is not expressible.
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

/// The vCPU a guest boots on, and — until ⑱-3b-ii — the only one that runs.
///
/// ⚠ **PRIVATE since ⑱-3b-i, and the privacy is the rung.** This constant used to be `pub(crate)`,
/// and `linux.rs` reached for it at six sites where the vCPU that mattered was the *running* one —
/// see [`VcpuIdx`] for the measurement. A per-vCPU decision made from a constant is not a defect a
/// reviewer can see, because the constant is correct at every site while there is only one vCPU. So
/// the constant stopped being nameable from there: [`VcpuIdx::boot`] is the only way out of this
/// module, and it says "the vCPU a guest boots on" at a call site rather than "0".
const BOOT_VCPU: usize = 0;

const _: () = assert!(
    BOOT_VCPU < VCPUS_PER_GUEST,
    "the boot vCPU must be one the guest actually has"
);

/// **A vCPU index that came from somewhere** — a role, or an explicit statement that boot is meant.
///
/// ## The defect, MEASURED at six sites rather than imagined
///
/// ⑱-3a made the vCPU axis a *type* on the state: `PendingSet` is `PerVcpu`, `DeployedGic` is
/// `PerGuest`, and putting either in the other container stops compiling. That closed the axis on
/// **declarations**. It did nothing for **call sites**, and the two are different defects:
///
/// ```ignore
/// VGIC.borrow_mut().at_mut(slot).is_enabled(BOOT_VCPU, intid)   // linux.rs:1519, before this rung
/// ```
///
/// The container is per-guest and correct; the *state* it indexes is per-vCPU and banked
/// (`GICR_ISENABLER0`, INTIDs 0..31 — ⑱-2's whole rung). `slot` is the running guest, and the vCPU is
/// a constant. At one vCPU per guest that constant is right at every site, so nothing — not the
/// compiler, not the boot gate, not a reviewer — can tell the six sites that mean "the running vCPU"
/// from the three that really mean "the boot vCPU".
///
/// **What each of the six does at two vCPUs**, and none of them is loud:
///
/// | site | consequence |
/// |---|---|
/// | timer mediation seam (`handle_linux_irq`) | decides the *running* vCPU's tick from vCPU 0's bank — vCPU 1 never ticks, or takes one it masked |
/// | the switch's re-arm of the physical PPI | the same read at the other moment the answer can change |
/// | the vGIC → physical redistributor mirror | the same read again, from the trap that changes it |
/// | the maintenance-interrupt drain | drains vCPU 0's pending set into vCPU 1's **live** list registers, and never drains vCPU 1's — so `UIE` stays armed over a set nothing empties |
/// | SGI deliver-or-defer | a full-bank SGI raised by vCPU 1 lands in vCPU 0's pending set |
/// | `set_guest_identity` on switch-in | every vCPU reads vCPU 0's `MPIDR_EL1` |
///
/// Two are **hangs**, three are **interrupts delivered to the wrong vCPU of the same guest** — the
/// exact class ⑱-3a's `LINUX_PENDING` finding was about, arriving one rung later through the other
/// door. The last one already has a measured death certificate: ⑱-1's kill probe gave a guest an
/// MPIDR its own device tree does not describe and it printed `missing boot CPU MPIDR, not enabling
/// secondaries` before panicking.
///
/// ## Why a type, when the module already says a bare index is right
///
/// [`PerGuest::at`] takes a plain slot, and `linux.rs`'s `guest_mpidr` argues at length that a
/// bare vCPU index is correct because there is exactly one subject. **Both of those stay true**, and
/// this type does not contradict them: it carries a vCPU and nothing else, so it cannot smuggle in
/// the "which guest" axis those arguments were about.
///
/// What it changes is *where an index can come from*. The defect above is not two roles confused in
/// one function — it is an axis **projected away and then re-supplied from a constant**. A type
/// closes exactly that: outside this module the only constructors are [`Running::vcpu`],
/// [`Incoming::vcpu`] and [`VcpuIdx::boot`], and `BOOT_VCPU` itself is no longer in scope to be
/// passed by mistake.
///
/// (There is no `Outgoing::vcpu`. It would be the obvious fourth, and **no site wants it** — every
/// per-vCPU decision here is about the vCPU that is *arriving* or the one that is *running*, never
/// the one leaving, whose per-vCPU state is reached through [`PerVcpu::out_mut`] with the whole
/// role. Adding it for symmetry is design-lesson #148, which this module has now applied three
/// times.)
///
/// ## ★ THE CEILING, stated before anyone reads more into this than it does
///
/// **Closed: supplying a CONSTANT where a role's vCPU was meant.** `is_enabled(BOOT_VCPU, ..)` does
/// not compile from `linux.rs` — the name does not resolve — and `is_enabled(0, ..)` does not
/// typecheck. Both were probed.
///
/// **NOT closed: supplying the WRONG ROLE's vCPU**, when the role is one you can name. That is the
/// same ceiling the module docs record for the guest axis, and ⑰-a's before it: **forgotten →
/// impossible, wrong → still compiles.** Nor is [`VcpuIdx::boot`] fenced off — it is a real
/// constructor, and writing it inside a switch compiles. What it cannot do is arrive there
/// *silently*, which is what a bare `0` spelled as a shared constant did.
///
/// ### The probes, all eight run, and two of them are the controls
///
/// | # | probe | result |
/// |---|---|---|
/// | 1 | `set_guest_identity(VcpuIdx::boot())` inside `switch_context` | `E0308` mismatched types |
/// | 2 | `is_enabled(0, intid)` at the mediation seam | `E0308` mismatched types |
/// | 3 | maintenance drain back to `LINUX_PENDING.at(slot, ..)` | `E0599` no method `at` |
/// | 4 | `use crate::role::BOOT_VCPU;` in `linux.rs` | `E0603` constant is private |
/// | 5 | `guest_mpidr(0)` — a bare integer | `E0308` mismatched types |
/// | 6 | `cur.vcpu()` where `next.vcpu()` was meant | `E0599` no method `vcpu` — **read the note** |
/// | 7 | **control:** a role fabricated on the spot, internally consistent | **builds clean** |
/// | 8 | **control:** `VcpuIdx::boot()` spelled out at the drain | **builds clean** |
///
/// ⚠ **Probe 6 is a build error FOR THE WRONG REASON, and saying so is the point of running it.**
/// The wrong-role slip does not compile inside `switch_context` today — not because roles are
/// enforced on this axis, but because `Outgoing::vcpu` **does not exist**, having had no caller (see
/// the module docs, #148). That is an accidental narrowing, not a designed fence, and it ends
/// quietly the day some rung adds that accessor for a legitimate reason. Probes 7 and 8 are what the
/// ceiling actually looks like, and they are here so nobody reads the five kills above as "a wrong
/// vCPU cannot compile". It can.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct VcpuIdx(usize);

impl VcpuIdx {
    /// **The vCPU a guest boots on**, for the three sites that genuinely mean it: the `const assert!`
    /// pinning `guest_mpidr` against `guest.dts`'s `cpu@0`, the `eret` that first enters guest A, and
    /// the context seeded for a guest's first entry.
    ///
    /// Deliberately a named constructor rather than an exported constant. The point of the rung is
    /// that "the boot vCPU" and "the running vCPU" stop being the same token; spelling one of them
    /// out at a call site is how a reader tells which was meant.
    pub(crate) const fn boot() -> Self {
        Self(BOOT_VCPU)
    }

    /// The index itself, for the arithmetic that has to happen somewhere — `MPIDR` derivation and
    /// array indexing. Reading the number out is not the hazard; **constructing** one from a bare
    /// integer is, and that is what this module keeps to itself.
    pub(crate) const fn get(self) -> usize {
        self.0
    }
}

/// The vCPU that is leaving the pCPU.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Outgoing {
    guest: usize,
    vcpu: VcpuIdx,
}

/// The vCPU that is arriving on the pCPU.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Incoming {
    guest: usize,
    vcpu: VcpuIdx,
}

/// The vCPU that holds the pCPU once a switch has completed.
///
/// Deliberately minimal: it exists only so [`Incoming::now_running`] has somewhere to go, which is
/// what lets `CURRENT` be stored without the switch ever holding a bare index.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Running {
    guest: usize,
    vcpu: VcpuIdx,
}

impl Outgoing {
    /// Name a guest's vCPU as the outgoing one. **The one place raw indices become this role** —
    /// keeping it explicit is what makes the seam reviewable.
    pub(crate) const fn at(guest: usize, vcpu: VcpuIdx) -> Self {
        Self { guest, vcpu }
    }
}

impl Incoming {
    /// Name a guest's vCPU as the incoming one.
    pub(crate) const fn at(guest: usize, vcpu: VcpuIdx) -> Self {
        Self { guest, vcpu }
    }

    /// Which of its guest's vCPUs this is. Read by the switch's identity write and its re-arm of the
    /// physical timer PPI — two decisions that are about the vCPU *arriving*, and that both used to
    /// name vCPU 0.
    pub(crate) const fn vcpu(self) -> VcpuIdx {
        self.vcpu
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
            vcpu: VcpuIdx::boot(),
        }
    }

    /// **Which vCPU of that guest is executing** — the accessor ⑱-3b-i exists to supply.
    ///
    /// The module docs used to record this as deliberately absent, on design-lesson #148's grounds
    /// that "⑱-3b will want it" is not a reason to ship API. It has a caller now, and in fact six:
    /// every handler that asks "which guest is running" and then makes a decision about state that
    /// is banked **per vCPU** — the timer mediation seam, the maintenance drain, the SGI defer. Each
    /// of those read a constant instead. See [`VcpuIdx`].
    pub(crate) const fn vcpu(self) -> VcpuIdx {
        self.vcpu
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
        self.guest * VCPUS_PER_GUEST + self.vcpu.get()
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
            vcpu: VcpuIdx(packed % VCPUS_PER_GUEST),
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
        &self.0[g.guest][g.vcpu.get()]
    }

    /// The **incoming** vCPU's element.
    pub(crate) fn inc(&self, g: Incoming) -> &T {
        &self.0[g.guest][g.vcpu.get()]
    }

    /// **The RUNNING vCPU's element** — one accessor for both axes, because a handler that asks
    /// "which guest" and "which vCPU" separately is exactly how ⑱-3b-i's defect was written.
    ///
    /// The two sites this replaces read `at(current_slot(), BOOT_VCPU)`: the guest axis projected
    /// out of [`Running`] and the vCPU axis supplied as a constant. Taking the whole role means the
    /// second half cannot be forgotten, which a plain-index accessor — correctly, for setup code —
    /// cannot promise. (That accessor, `PerVcpu::at`, had no callers left afterwards and was
    /// removed; see the module docs.)
    pub(crate) fn of(&self, r: Running) -> &T {
        &self.0[r.guest][r.vcpu.get()]
    }

    /// The **outgoing** vCPU's element, mutably.
    pub(crate) fn out_mut(&mut self, g: Outgoing) -> &mut T {
        &mut self.0[g.guest][g.vcpu.get()]
    }

    /// The **incoming** vCPU's element, mutably.
    pub(crate) fn inc_mut(&mut self, g: Incoming) -> &mut T {
        &mut self.0[g.guest][g.vcpu.get()]
    }

    /// An arbitrary vCPU, mutably — setup code only.
    pub(crate) fn at_mut(&mut self, guest: usize, vcpu: VcpuIdx) -> &mut T {
        &mut self.0[guest][vcpu.get()]
    }
}
