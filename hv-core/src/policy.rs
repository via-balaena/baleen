// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Scheduling policy — the layer that *picks*
//!
//! [`crate::sched`] is deliberately mechanism-only: it moves a vCPU onto a physical
//! CPU but refuses to choose *which* runnable vCPU deserves one. This module is that
//! choice. It sits **above** the dispatch seam, not inside it — a guest never asks to
//! be scheduled; the hypervisor's own timer tick and idle path invoke a [`Scheduler`],
//! which then drives the mechanism's public transitions. Because it enacts only
//! through [`sched::System::run`] / [`sched::System::preempt`], every decision it
//! makes is still guarded by the mechanism's invariants — the policy cannot corrupt
//! pCPU exclusivity even if its own logic is wrong.
//!
//! **What it is vs. what the mechanism is.** The mechanism has a *safety invariant*
//! (one vCPU per pCPU, checked every transition). A policy has no safety invariant of
//! its own; what it has instead are *properties* worth proving, and this one is built to hold
//! **four**. ⚠ **This used to gloss that as "a bad policy is unfair, not unsafe", and ㉘ deleted
//! the gloss rather than softening it** — see the paragraph below, where a wrong choice here
//! stopped the machine outright while every invariant held. The mechanism still cannot be
//! *corrupted* from up here; that is a narrower guarantee than the phrase implied.
//!
//! ⚠ This line said **three** while four were listed below — sleeper-fairness was added without
//! the count moving. Nothing gates a count inside a module doc, which is exactly why a number in
//! prose is a liability (design-lesson #276). Corrected, not quietly reworded.
//!
//! ⚠⚠ **"Worth proving" is the operative phrase: ONE of the four is proven, and three are not.**
//! This module sits in `hv-core` — the crate whose isolation core is machine-checked — and a
//! reader is entitled to assume its contents carry that tier. **Mostly they still do not.**
//!
//! * **Work conservation is machine-checked since ㉘**, by
//!   `hv-verify`'s `policy_work_conservation::advance_leaves_no_legal_dispatch_unmade` — the first
//!   Kani harness over this module or [`crate::sched`]. It drives the real [`Scheduler::advance`]
//!   over a symbolic admission pattern and symbolic per-vCPU affinity, then requires that the
//!   mechanism refuse every remaining dispatch. ⚠ **At a bounded shape** (1 domain × 2 vCPUs ×
//!   2 pCPUs, concrete quantum, `now = 0`) — ∀-values on the axes that are symbolic, not ∀-size.
//! * **The other three are still `hv-sim` seeded simulation**, the project's weakest tier, and
//!   **two of them cannot be Kani's** at any shape: proportional fairness is a statement about a
//!   *limit*, and the starvation bound is a statement about *unbounded runs*. Neither is a
//!   bounded-depth property, so closing them means a different technique, not a bigger harness.
//!
//! ★★ **And the warning this paragraph used to carry was not hypothetical — it had already come
//! true when it was written.** It said a policy has no safety invariant, so a bad one is "unfair
//! rather than unsafe", and that the proven mechanism beneath cannot be corrupted by a wrong
//! choice here. Both clauses are true and both were beside the point: ㉘ found that the
//! work-conservation property **was simply false**, and its failure mode was neither unfairness
//! nor corruption but a **total, permanent scheduling stall** — every CPU idle, every vCPU
//! runnable, zero transitions, forever (see [`Scheduler::next`]). The mechanism's invariants held
//! perfectly throughout. **"It cannot break the proven layer beneath" is not the same as "it
//! works", and a module doc that reaches for the first when a reader wants the second is telling
//! them something true and useless.**
//!
//! ⚠ **The residual that matters most is still open.** Anything depending on the *latency* bound —
//! a safety monitor, say — is depending on a simulation result while a reader of this crate would
//! assume a proof. That is exactly what ㉘ did **not** close.
//!
//! * **Work-conserving** — it never leaves a physical CPU idle while a vCPU **that may use that
//!   CPU** is runnable. After [`Scheduler::advance`] settles, no idle-CPU/waiting-vCPU pair
//!   remains *where the waiter's hard affinity admits that CPU*.
//!   ⚠⚠ **The qualification is load-bearing and its absence was a real defect, not pedantry.**
//!   A vCPU whose mask excludes every free CPU is `Runnable` and legitimately unplaceable —
//!   `set_affinity(_, _, 0)` is accepted — so the unqualified sentence is unsatisfiable rather
//!   than merely strict. It stood here for four arcs, and read as true the whole time, because
//!   **no tier that checked it ever set an affinity mask**: `hv-sim`'s `run_policy` churn and the
//!   `hv-fuzz` `policy` target drew from the same four-op alphabet, so every mask stayed full in
//!   every run of both. ★ Two tiers sharing one blind axis are one tier with two names.
//! * **Weighted-proportional-fair** — each vCPU carries a [`Weight`]; over time the
//!   CPU splits between continuously-runnable vCPUs in proportion to their weights,
//!   because the policy always runs the one with the least *service per weight*.
//! * **Starvation-free, with a MEASURED BOUND rather than "eventually"** — a
//!   [`Scheduler::quantum`] time-slice forces a running vCPU to yield to a more-deserving
//!   waiter. The worst observed wait for a continuously-runnable vCPU `i` is
//!   `(W_total − wᵢ) × quantum / pcpus + 1`, matched exactly across five configurations by
//!   `hv-sim`'s `policy_bounds_scheduling_latency`.
//!   ⚠ **Note what that bound is a function of: the WEIGHTS of the other vCPUs, not their
//!   number.** The count-based intuition `(vcpus − pcpus) × quantum` predicts 4 for weights
//!   `[1,2,3]` where the real answer is 11 — so adding a *heavy* neighbour lengthens a vCPU's
//!   worst case without adding a vCPU. Anything with a latency requirement (a safety monitor,
//!   say) has to budget against the configured weights.
//!   ⚠ **Aggregate fairness does not imply this**, and the two are checked separately:
//!   `policy_starves_no_one` bounds each vCPU's *share*, which a vCPU can satisfy while taking
//!   its whole portion in two blocks around one enormous gap.
//! * **Sleeper-fair** — [wake-boost](Scheduler::set_wake_boost) places a vCPU that
//!   re-enters the runnable pool (from `Blocked`, or freshly `admit`ted) at the pool's
//!   *floor*, not below it. Without this, a vCPU that slept — and so accrued no
//!   service while the others ran — would, on waking, look infinitely more deserving
//!   and monopolise a CPU to "catch up", starving the vCPUs that stayed runnable. This
//!   is the scheduler's version of CFS's `place_entity`.
//!
//! **Lean by design.** The fairness signal is the run time the mechanism *already*
//! tracks ([`sched::System::runtime`]) plus the current interval
//! ([`sched::System::on_cpu_since`]); the policy adds only configuration — per-vCPU
//! weights and one quantum — and the small bookkeeping wake-boost needs (a per-vCPU
//! service offset, set on the wake edge, and a snapshot of who was schedulable last).
//! A continuously-runnable vCPU never wakes, so its offset stays zero and it is ranked
//! on raw service exactly as before — wake-boost only corrects the vCPUs that leave
//! and rejoin the pool. Further refinements (a latency credit that places sleepers
//! slightly *ahead* of the floor for interactivity, credit replenishment, per-pCPU run
//! queues) layer on top of this without disturbing the mechanism beneath.
//!
//! Provenance: weighted proportional-share selection (least virtual-runtime-first)
//! and quantum-based preemption are textbook fair-scheduling mechanics from general
//! OS literature (WFQ / CFS / stride-style share scheduling) — not derived from
//! `xen/`'s GPL credit/credit2 schedulers. See `CLEANROOM.md`.

extern crate alloc;

use alloc::vec::Vec;

use hv_hal::Ticks;

use crate::sched::{self, DomId, Pcpu, RunState, Vcpu};

/// A vCPU's scheduling weight — its proportional share of the CPU. A vCPU with
/// weight `2w` earns, in the limit, twice the run time of one with weight `w` while
/// both stay runnable. The minimum (and default) weight is `1`; weight `0` is
/// meaningless for a proportional share and is clamped up.
pub type Weight = u32;

/// The smallest legal weight. `0` would divide by zero in a share computation, so it
/// is clamped to this.
pub const MIN_WEIGHT: Weight = 1;

/// One scheduling decision the policy recommends. The caller enacts it against the
/// [`sched::System`] mechanism (which re-checks its own invariants); the policy never
/// mutates scheduler state except through that public mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Dispatch this runnable vCPU onto this idle physical CPU.
    Run { dom: DomId, vcpu: Vcpu, pcpu: Pcpu },
    /// Preempt this running vCPU (its quantum has expired and a more-deserving vCPU **affine to
    /// this physical CPU** is waiting), freeing its physical CPU for the next [`Decision::Run`].
    Preempt { dom: DomId, vcpu: Vcpu, pcpu: Pcpu },
    /// Nothing to do: no vCPU is runnable, or every runnable vCPU that could legally take a free
    /// CPU is already running, or the only waiters are barred by affinity from every free CPU —
    /// and no preemption is warranted.
    Idle,
}

/// A weighted-proportional-fair, work-conserving scheduling policy over a
/// [`sched::System`]. Its fairness signal is the run time the mechanism already
/// tracks; the only state it owns is configuration (per-vCPU weights, a time-slice
/// quantum) plus the small bookkeeping [wake-boost](Scheduler::set_wake_boost) needs —
/// a per-vCPU service offset and a snapshot of who was schedulable last, so a wake
/// edge can be spotted.
pub struct Scheduler {
    /// `weights[dom][vcpu]`. Sized to match the mechanism it drives; lookups outside
    /// range fall back to [`MIN_WEIGHT`], so a shape mismatch is safe, not a panic.
    weights: Vec<Vec<Weight>>,
    /// The time-slice: a running vCPU becomes preemptible once it has held its CPU
    /// for at least this many ticks.
    quantum: Ticks,
    /// `offset[dom][vcpu]`: extra service (in ticks) added on top of the mechanism's
    /// tracked runtime when ranking a vCPU. Wake-boost raises this on the edge into
    /// the runnable pool so a long-slept (or freshly admitted) vCPU is placed at the
    /// pack's floor instead of dominating with its stale-low service. Zero for a vCPU
    /// that never leaves the runnable pool — so continuously-runnable vCPUs are ranked
    /// on raw service exactly as before.
    offset: Vec<Vec<u128>>,
    /// `was_schedulable[dom][vcpu]`: whether the vCPU was `Runnable` or `Running` at
    /// the last accounting pass, so the transition *into* the pool (a wake) is
    /// detectable.
    was_schedulable: Vec<Vec<bool>>,
    /// Whether wake-boost is applied. On by default; a caller can disable it to get
    /// the raw least-service-first behaviour (useful to show the difference).
    wake_boost: bool,
}

impl Scheduler {
    /// A policy for `num_domains` domains of `vcpus_per_domain` vCPUs each, every vCPU
    /// at the default weight, with time-slice `quantum` and wake-boost on. A `quantum`
    /// of `0` makes a running vCPU preemptible immediately (pure least-service-first,
    /// maximal fairness, maximal context switching).
    pub fn new(num_domains: usize, vcpus_per_domain: usize, quantum: Ticks) -> Self {
        Scheduler {
            weights: (0..num_domains)
                .map(|_| alloc::vec![MIN_WEIGHT; vcpus_per_domain])
                .collect(),
            quantum,
            offset: (0..num_domains)
                .map(|_| alloc::vec![0u128; vcpus_per_domain])
                .collect(),
            was_schedulable: (0..num_domains)
                .map(|_| alloc::vec![false; vcpus_per_domain])
                .collect(),
            wake_boost: true,
        }
    }

    /// Enable or disable wake-boost (on by default). With it off, a vCPU entering the
    /// runnable pool is ranked on its raw accumulated service — so a long-slept or
    /// newly-admitted vCPU will monopolise a CPU to "catch up", starving the vCPUs
    /// that stayed runnable. With it on, such a vCPU is placed at the pool's floor and
    /// simply shares fairly from there. Clears any offsets accumulated so far.
    pub fn set_wake_boost(&mut self, enabled: bool) {
        self.wake_boost = enabled;
        for row in &mut self.offset {
            for o in row.iter_mut() {
                *o = 0;
            }
        }
    }

    /// Set a vCPU's weight (clamped to at least [`MIN_WEIGHT`]). Out-of-range ids are
    /// ignored — the policy is configured against a known shape.
    pub fn set_weight(&mut self, dom: DomId, vcpu: Vcpu, weight: Weight) {
        if let Some(w) = self
            .weights
            .get_mut(dom as usize)
            .and_then(|d| d.get_mut(vcpu as usize))
        {
            *w = weight.max(MIN_WEIGHT);
        }
    }

    /// A vCPU's configured weight (at least [`MIN_WEIGHT`], the default for any vCPU
    /// never set or out of range).
    pub fn weight_of(&self, dom: DomId, vcpu: Vcpu) -> Weight {
        self.weights
            .get(dom as usize)
            .and_then(|d| d.get(vcpu as usize))
            .copied()
            .unwrap_or(MIN_WEIGHT)
            .max(MIN_WEIGHT)
    }

    /// The time-slice quantum.
    pub fn quantum(&self) -> Ticks {
        self.quantum
    }

    /// Recommend the single next action for the mechanism state `sys` at time `now`,
    /// without mutating anything. Pure: identical `(sys, now)` yield an identical
    /// [`Decision`]. [`Self::advance`] calls this in a loop; it is exposed on its own
    /// so the decision logic can be unit-tested with no mutation in the loop.
    ///
    /// The rule, in order:
    /// 1. If any runnable vCPU can legally take an idle physical CPU, [`Decision::Run`] the
    ///    least-serviced-per-weight such vCPU on the lowest-numbered idle CPU **its affinity
    ///    admits** (work conservation).
    /// 2. Otherwise, if some running vCPU's quantum has expired and a strictly-more-deserving
    ///    waiter is affine to *that* CPU, [`Decision::Preempt`] the least deserving such runner
    ///    (the following `next` will then run the waiter).
    /// 3. Otherwise [`Decision::Idle`].
    ///
    /// ⚠⚠ **Both rules are affinity-aware, and neither was before ㉘.** The earlier form chose
    /// the globally most-deserving runnable vCPU and *then* looked for an idle CPU, consulting no
    /// mask — so it would recommend a dispatch [`sched::System::run`] refuses with `NotAffine`,
    /// whereupon [`Self::advance`] took the `Err` as its `break` and **abandoned the whole
    /// fixpoint**. One vCPU pinned away from the lowest idle CPU therefore stopped the machine:
    /// measured at 0 transitions over 200 ticks on a 2-vCPU/2-pCPU system, permanently, starving
    /// the *other* vCPU too — which was legally placeable the entire time. It was permanent
    /// because the unplaceable vCPU is the most deserving precisely *because* it never runs, so
    /// the choice repeated forever.
    ///
    /// ★ **Choosing the most-deserving *placeable* vCPU is what makes it right, not merely
    /// choosing an affine CPU for the most-deserving one.** If the best candidate has no affine
    /// idle CPU while a worse one does, work conservation obliges us to run the worse one.
    /// Likewise rule 2 pairs a waiter with a runner it could actually replace: freeing a CPU no
    /// waiter may use is a context switch that buys nothing and leaves the same CPU idle.
    ///
    /// **With every mask full both rules reduce exactly to the old behaviour** — which is why
    /// every existing test, the seeded simulation and the fuzz target all continued to pass, and
    /// why none of them ever saw the defect.
    pub fn next(&self, sys: &sched::System, now: Ticks) -> Decision {
        // Rule 1 — fill an idle CPU with the most-deserving vCPU that can legally use one.
        if let Some((dom, vcpu, pcpu)) = self.best_placement(sys, now) {
            return Decision::Run { dom, vcpu, pcpu };
        }

        // Rule 2 — no legal placement left: preempt for a strictly-more-deserving affine waiter.
        if let Some((dom, vcpu, pcpu)) = self.best_preemption(sys, now) {
            return Decision::Preempt { dom, vcpu, pcpu };
        }

        Decision::Idle
    }

    /// Drive `sys` to a scheduling fixpoint at time `now`: first account for wake
    /// events (see [`Self::set_wake_boost`]), then enact [`Self::next`] until it returns
    /// [`Decision::Idle`]. Returns the number of transitions enacted. This is the thin
    /// driver the hypervisor's tick/idle path calls; it mutates the mechanism only
    /// through its public transitions, so the mechanism's invariants hold throughout.
    ///
    /// Terminates: each [`Decision::Run`] consumes an idle CPU, and each
    /// [`Decision::Preempt`] targets a vCPU whose quantum has expired and replaces it
    /// (via the following `Run`) with one just dispatched at `now` — elapsed `0`, not
    /// re-preemptible at this `now` — so at most one preemption occurs per physical
    /// CPU per call.
    pub fn advance(&mut self, sys: &mut sched::System, now: Ticks) -> u32 {
        // Fold in any wake edges before deciding, so a just-woken vCPU is placed at the
        // pool's floor rather than ranked on its stale-low service.
        self.account(sys, now);
        let mut enacted = 0;
        // Bound the loop defensively so a hypothetical non-converging `next` cannot
        // spin forever. Least-service-first is a total order, so `advance` moves
        // monotonically toward the fixpoint (the most-deserving vCPUs running); this
        // cap — every vCPU placed once, plus a preempt/refill margin per CPU — is far
        // above what convergence needs. If it were ever hit, the caller's
        // work-conservation check would notice, so it fails loud, not silent.
        let total_vcpus: usize = (0..sys.domain_count() as DomId)
            .map(|d| sys.vcpu_count(d))
            .sum();
        let limit = (total_vcpus + 2 * sys.pcpu_count() + 1) as u32;
        for _ in 0..limit {
            match self.next(sys, now) {
                Decision::Run { dom, vcpu, pcpu } => {
                    // Enacted through the public mechanism; it re-checks exclusivity.
                    //
                    // ⚠⚠ **This `break` was load-bearing before ㉘ and is defensive after it.**
                    // `next` used to recommend off-affinity dispatches, so `run` really did
                    // refuse — and taking that refusal as `break` abandoned the whole fixpoint,
                    // leaving CPUs idle with placeable vCPUs waiting. Now every refusal reason is
                    // excluded before we get here: `next` returns `Run` only for a `Runnable`
                    // vCPU (not `WrongState`), on an in-range pCPU (not `BadPcpu`) that is
                    // unoccupied (not `PcpuBusy`) and in its mask (not `NotAffine`).
                    //
                    // ⚠ **Unreachable by construction, NOT by proof.** The work-conservation
                    // harness would fail if this fired at its shape, which is evidence rather
                    // than a theorem; nothing yet asserts the stronger "`next` never proposes a
                    // decision the mechanism refuses" directly. Keep the `break`: if a future
                    // rule reintroduces a refusal, stopping is safer than looping on it.
                    if sys.run(dom, vcpu, pcpu, now).is_err() {
                        break;
                    }
                }
                Decision::Preempt { dom, vcpu, .. } => {
                    // Likewise: `next` names a vCPU it just observed `Running`, so `preempt`
                    // cannot refuse it.
                    if sys.preempt(dom, vcpu, now).is_err() {
                        break;
                    }
                }
                Decision::Idle => break,
            }
            enacted += 1;
        }
        enacted
    }

    // ─── internals ────────────────────────────────────────────────────────────

    /// The most-deserving runnable vCPU that can be placed *right now*, paired with the pCPU it
    /// would take: least service-per-weight among those with an affine idle CPU, ties broken by
    /// lowest `(dom, vcpu)` for determinism. `None` when no runnable vCPU has one — every CPU
    /// busy, or every free CPU outside every waiter's mask.
    ///
    /// ⚠ **The placeability test is part of the *selection*, not a filter applied afterwards.**
    /// Ranking first and checking affinity second is the defect ㉘ closed: it lets an unplaceable
    /// front-runner mask a placeable candidate behind it, and since that front-runner accrues no
    /// service while it waits, it stays the front-runner forever.
    fn best_placement(&self, sys: &sched::System, now: Ticks) -> Option<(DomId, Vcpu, Pcpu)> {
        let mut best: Option<((DomId, Vcpu, Pcpu), Share)> = None;
        for dom in 0..sys.domain_count() as DomId {
            for vcpu in 0..sys.vcpu_count(dom) as Vcpu {
                if sys.state_of(dom, vcpu) != Some(RunState::Runnable) {
                    continue;
                }
                let pcpu = match self.first_idle_pcpu_for(sys, dom, vcpu) {
                    Some(p) => p,
                    None => continue,
                };
                let share = self.share(sys, dom, vcpu, now);
                // Strictly-more-deserving keeps the earliest index on a tie.
                if best.map(|(_, b)| more_deserving(share, b)).unwrap_or(true) {
                    best = Some(((dom, vcpu, pcpu), share));
                }
            }
        }
        best.map(|(id, _)| id)
    }

    /// Among running vCPUs whose quantum has expired **and whose CPU some strictly-more-deserving
    /// waiter is affine to**, the *least* deserving (greatest service-per-weight) — the best
    /// candidate to evict. Ties broken by lowest `(dom, vcpu)`. `None` if no such runner exists.
    ///
    /// ⚠ The affinity condition is what keeps a preemption *useful*. Evicting a runner from a CPU
    /// no waiter may occupy frees it for nobody: the following `next` cannot place the waiter
    /// there, so the eviction costs a context switch and leaves the CPU idle — and it breaks the
    /// bound [`Self::advance`] relies on, which assumes the CPU a preemption frees is one the
    /// waiter that motivated it can take.
    fn best_preemption(&self, sys: &sched::System, now: Ticks) -> Option<(DomId, Vcpu, Pcpu)> {
        let mut worst: Option<((DomId, Vcpu, Pcpu), Share)> = None;
        for dom in 0..sys.domain_count() as DomId {
            for vcpu in 0..sys.vcpu_count(dom) as Vcpu {
                let pcpu = match sys.state_of(dom, vcpu) {
                    Some(RunState::Running { pcpu }) => pcpu,
                    _ => continue,
                };
                let since = sys.on_cpu_since(dom, vcpu).unwrap_or(now);
                if now.saturating_sub(since) < self.quantum {
                    continue; // still within its time-slice
                }
                let share = self.share(sys, dom, vcpu, now);
                if !self.some_affine_waiter_beats(sys, pcpu, share, now) {
                    continue; // freeing this CPU would help nobody
                }
                // Replace when the tracked worst is strictly more deserving than this
                // one (i.e. this one is less deserving); strictness keeps the earliest
                // index on a tie.
                if worst.map(|(_, b)| more_deserving(b, share)).unwrap_or(true) {
                    worst = Some(((dom, vcpu, pcpu), share));
                }
            }
        }
        worst.map(|(id, _)| id)
    }

    /// Whether some `Runnable` vCPU affine to `pcpu` is strictly more deserving than `runner` —
    /// i.e. whether evicting the vCPU currently on `pcpu` would actually hand it to a better
    /// claimant.
    fn some_affine_waiter_beats(
        &self,
        sys: &sched::System,
        pcpu: Pcpu,
        runner: Share,
        now: Ticks,
    ) -> bool {
        for dom in 0..sys.domain_count() as DomId {
            for vcpu in 0..sys.vcpu_count(dom) as Vcpu {
                if sys.state_of(dom, vcpu) != Some(RunState::Runnable)
                    || !sys.affinity_permits(dom, vcpu, pcpu)
                {
                    continue;
                }
                if more_deserving(self.share(sys, dom, vcpu, now), runner) {
                    return true;
                }
            }
        }
        false
    }

    /// A vCPU's proportional-share position as the rational `service / weight`, kept
    /// as its numerator/denominator pair so it can be compared exactly with
    /// cross-multiplication (no division, no float). `service` is effective runtime:
    /// closed on-CPU intervals, plus the current in-flight one (so a running vCPU is
    /// not flattered by its unaccounted time), plus its wake-boost `offset` (so a
    /// just-woken vCPU sits at the pool's floor, not below it).
    fn share(&self, sys: &sched::System, dom: DomId, vcpu: Vcpu, now: Ticks) -> Share {
        let closed = u128::from(sys.runtime(dom, vcpu).unwrap_or(0));
        let in_flight = match sys.on_cpu_since(dom, vcpu) {
            Some(since) => u128::from(now.saturating_sub(since)),
            None => 0,
        };
        Share {
            service: closed + in_flight + self.offset_of(dom, vcpu),
            weight: u128::from(self.weight_of(dom, vcpu)),
        }
    }

    /// Fold in wake edges: any vCPU that entered the runnable pool (from `Blocked` or
    /// `Offline`) since the last call is placed at the pool's *floor* — the minimum
    /// service-per-weight among the vCPUs that were already there — so its stale-low
    /// service cannot let it monopolise a CPU to catch up. Only ever raises a vCPU's
    /// standing (a boost, never a penalty), and does nothing for a vCPU that never
    /// left the pool, so continuously-runnable vCPUs keep ranking on raw service.
    fn account(&mut self, sys: &sched::System, now: Ticks) {
        // Pass 1: the floor of the established pack — vCPUs schedulable now *and* at
        // the last snapshot, so this tick's wakers do not anchor to each other.
        let mut floor: Option<Share> = None;
        for dom in 0..sys.domain_count() as DomId {
            for vcpu in 0..sys.vcpu_count(dom) as Vcpu {
                if schedulable(sys, dom, vcpu) && self.was_schedulable(dom, vcpu) {
                    let s = self.share(sys, dom, vcpu, now);
                    if floor.map(|f| more_deserving(s, f)).unwrap_or(true) {
                        floor = Some(s);
                    }
                }
            }
        }

        // Pass 2: place each waker at the floor (if boost is on), then refresh the
        // snapshot for next time.
        for dom in 0..sys.domain_count() as DomId {
            for vcpu in 0..sys.vcpu_count(dom) as Vcpu {
                let now_sched = schedulable(sys, dom, vcpu);
                let woke = now_sched && !self.was_schedulable(dom, vcpu);
                if woke && self.wake_boost {
                    if let Some(f) = floor {
                        // Target service so `target / weight == floor.service / floor.weight`.
                        let weight = u128::from(self.weight_of(dom, vcpu));
                        let target = f.service.saturating_mul(weight) / f.weight;
                        let raw = u128::from(sys.runtime(dom, vcpu).unwrap_or(0));
                        // Boost only: never drag a vCPU that is already above the floor
                        // back down.
                        self.set_offset(dom, vcpu, target.saturating_sub(raw));
                    }
                }
                self.set_was_schedulable(dom, vcpu, now_sched);
            }
        }
    }

    /// The lowest-numbered idle pCPU this vCPU's affinity admits, if any. `None` means the vCPU
    /// cannot be dispatched at this instant — either every CPU is occupied, or none of the free
    /// ones is in its mask. The affinity question is put to [`sched::System::affinity_permits`],
    /// the same predicate [`sched::System::run`] enforces, so the policy cannot be testing a
    /// different rule from the one that will judge its recommendation.
    fn first_idle_pcpu_for(&self, sys: &sched::System, dom: DomId, vcpu: Vcpu) -> Option<Pcpu> {
        (0..sys.pcpu_count() as Pcpu)
            .find(|&p| sys.occupant(p).is_none() && sys.affinity_permits(dom, vcpu, p))
    }

    fn offset_of(&self, dom: DomId, vcpu: Vcpu) -> u128 {
        self.offset
            .get(dom as usize)
            .and_then(|r| r.get(vcpu as usize))
            .copied()
            .unwrap_or(0)
    }

    fn set_offset(&mut self, dom: DomId, vcpu: Vcpu, value: u128) {
        if let Some(o) = self
            .offset
            .get_mut(dom as usize)
            .and_then(|r| r.get_mut(vcpu as usize))
        {
            *o = value;
        }
    }

    fn was_schedulable(&self, dom: DomId, vcpu: Vcpu) -> bool {
        self.was_schedulable
            .get(dom as usize)
            .and_then(|r| r.get(vcpu as usize))
            .copied()
            .unwrap_or(false)
    }

    fn set_was_schedulable(&mut self, dom: DomId, vcpu: Vcpu, value: bool) {
        if let Some(s) = self
            .was_schedulable
            .get_mut(dom as usize)
            .and_then(|r| r.get_mut(vcpu as usize))
        {
            *s = value;
        }
    }
}

/// Whether a vCPU is in the runnable pool — `Runnable` or `Running`, the states that
/// carry a live scheduling position (as opposed to `Blocked` / `Offline`).
fn schedulable(sys: &sched::System, dom: DomId, vcpu: Vcpu) -> bool {
    matches!(
        sys.state_of(dom, vcpu),
        Some(RunState::Runnable | RunState::Running { .. })
    )
}

/// A vCPU's fair-share position as the rational `service / weight`. Compared by
/// [`more_deserving`], which cross-multiplies so the ordering is exact.
#[derive(Debug, Clone, Copy)]
struct Share {
    /// Effective on-CPU service (ticks).
    service: u128,
    /// Scheduling weight (at least [`MIN_WEIGHT`], so never zero).
    weight: u128,
}

/// Is `a` strictly more deserving of a CPU than `b`? A vCPU is more deserving when it
/// has received *less* service per unit weight — `a.service / a.weight <
/// b.service / b.weight` — tested by cross-multiplication in `u128` so it is exact
/// and division-free. Both weights are at least [`MIN_WEIGHT`], so neither product is
/// a divide-by-zero in disguise. The products are `saturating_mul`: exact for every
/// realistic (service, weight), and at pathological magnitudes (a `~u32::MAX` weight
/// times a `~2^64` service) they clamp rather than overflow — a benign tie at the
/// extreme instead of a debug panic / release wrap.
fn more_deserving(a: Share, b: Share) -> bool {
    a.service.saturating_mul(b.weight) < b.service.saturating_mul(a.weight)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A 2-domain system, 2 vCPUs each, over 1 physical CPU — contention on purpose,
    // so fairness and preemption both bite.
    fn setup(quantum: Ticks) -> (sched::System, Scheduler) {
        (sched::System::new(2, 2, 1), Scheduler::new(2, 2, quantum))
    }

    #[test]
    fn idle_when_nothing_is_runnable() {
        let (sys, pol) = setup(10);
        assert_eq!(pol.next(&sys, 0), Decision::Idle);
    }

    #[test]
    fn runs_a_runnable_vcpu_on_the_idle_cpu() {
        let (mut sys, pol) = setup(10);
        sys.admit(1, 0).unwrap();
        assert_eq!(
            pol.next(&sys, 0),
            Decision::Run {
                dom: 1,
                vcpu: 0,
                pcpu: 0
            }
        );
    }

    #[test]
    fn advance_is_work_conserving_until_the_cpu_is_full() {
        let (mut sys, mut pol) = setup(10);
        sys.admit(0, 0).unwrap();
        sys.admit(0, 1).unwrap();
        // One CPU, two runnable vCPUs: advance fills the CPU and then, with no
        // quantum elapsed, stops — one running, one waiting, CPU busy.
        pol.advance(&mut sys, 0);
        assert_eq!(sys.busy_pcpus(), 1);
        // Nothing more to do at the same instant: the runner's quantum has not passed.
        assert_eq!(pol.next(&sys, 0), Decision::Idle);
    }

    #[test]
    fn picks_the_least_serviced_per_weight() {
        let (mut sys, pol) = setup(10);
        // vcpu (0,0) has already run 100 ticks; (0,1) has run nothing.
        sys.admit(0, 0).unwrap();
        sys.run(0, 0, 0, 0).unwrap();
        sys.preempt(0, 0, 100).unwrap(); // (0,0) now has runtime 100, runnable
        sys.admit(0, 1).unwrap(); // (0,1) has runtime 0, runnable
                                  // Both runnable, CPU idle: the unserved one wins.
        assert_eq!(
            pol.next(&sys, 100),
            Decision::Run {
                dom: 0,
                vcpu: 1,
                pcpu: 0
            }
        );
    }

    #[test]
    fn weight_tilts_the_choice() {
        let (mut sys, mut pol) = setup(10);
        // Both have run 100 ticks, but (0,1) has double weight, so its service/weight
        // is lower — it is more deserving.
        sys.admit(0, 0).unwrap();
        sys.run(0, 0, 0, 0).unwrap();
        sys.preempt(0, 0, 100).unwrap();
        sys.admit(0, 1).unwrap();
        sys.run(0, 1, 0, 0).unwrap();
        sys.preempt(0, 1, 100).unwrap();
        pol.set_weight(0, 1, 2);
        assert_eq!(
            pol.next(&sys, 100),
            Decision::Run {
                dom: 0,
                vcpu: 1,
                pcpu: 0
            }
        );
    }

    #[test]
    fn preempts_a_runner_past_its_quantum_for_a_waiter() {
        let (mut sys, pol) = setup(10);
        // (0,0) runs from t=0; (0,1) is admitted and waits.
        sys.admit(0, 0).unwrap();
        sys.run(0, 0, 0, 0).unwrap();
        sys.admit(0, 1).unwrap();
        // Before the quantum: no preemption (both would be equally deserving, and the
        // runner is not yet expired).
        assert_eq!(pol.next(&sys, 5), Decision::Idle);
        // After the quantum: (0,0) has run 15 ticks, (0,1) still 0 — evict (0,0).
        assert_eq!(
            pol.next(&sys, 15),
            Decision::Preempt {
                dom: 0,
                vcpu: 0,
                pcpu: 0
            }
        );
    }

    #[test]
    fn no_preemption_when_the_runner_is_more_deserving() {
        let (mut sys, mut pol) = setup(10);
        // The waiter (0,1) has already been heavily serviced; the runner (0,0) has a
        // big weight, so even past quantum the runner still deserves the CPU more.
        pol.set_weight(0, 0, 100);
        sys.admit(0, 1).unwrap();
        sys.run(0, 1, 0, 0).unwrap();
        sys.preempt(0, 1, 500).unwrap(); // (0,1) serviced 500, now waiting
        sys.admit(0, 0).unwrap();
        sys.run(0, 0, 0, 500).unwrap(); // (0,0) starts running at t=500
                                        // Past its quantum, but its service/weight (≈0) beats the waiter's (500) —
                                        // keep it.
        assert_eq!(pol.next(&sys, 520), Decision::Idle);
    }

    #[test]
    fn wake_boost_places_a_newcomer_at_the_floor_not_ahead() {
        let (mut sys, mut pol) = setup(10);
        // A = (0,0) runs alone from t=0 and accrues a large service.
        sys.admit(0, 0).unwrap();
        pol.advance(&mut sys, 0);
        assert!(sys.is_running(0, 0));
        // Much later, a fresh vCPU B = (0,1) is admitted with zero accrued service.
        sys.admit(0, 1).unwrap();
        pol.advance(&mut sys, 1000);
        // Wake-boost places B at A's level, so B does NOT preempt A to catch up: the
        // incumbent keeps the CPU and B waits its fair turn.
        assert_eq!(
            sys.occupant(0),
            Some((0, 0)),
            "a boosted newcomer must not evict the incumbent to catch up"
        );
        assert_eq!(sys.state_of(0, 1), Some(RunState::Runnable));
    }

    #[test]
    fn without_wake_boost_a_newcomer_hogs_the_cpu() {
        let (mut sys, mut pol) = setup(10);
        pol.set_wake_boost(false);
        sys.admit(0, 0).unwrap();
        pol.advance(&mut sys, 0);
        assert!(sys.is_running(0, 0));
        sys.admit(0, 1).unwrap();
        pol.advance(&mut sys, 1000);
        // Ranked on raw service, the zero-service newcomer looks infinitely more
        // deserving and immediately evicts the long-running incumbent — exactly the
        // unfairness wake-boost exists to prevent.
        assert_eq!(
            sys.occupant(0),
            Some((0, 1)),
            "an unboosted newcomer preempts and seizes the CPU"
        );
    }

    /// ㉘ — the regression. A vCPU pinned away from the lowest idle CPU used to make the policy
    /// recommend a dispatch the mechanism refuses (`NotAffine`), which `advance` took as its
    /// `break`, abandoning the fixpoint before placing *anybody*. Both CPUs then sat idle with
    /// both vCPUs `Runnable`, forever: measured at 0 transitions over 200 ticks, because the
    /// unplaceable vCPU stays the most deserving precisely by never running.
    ///
    /// ★ Note what this asserts about the *innocent* vCPU. (0,1) is affine to everything and was
    /// legally placeable the whole time; the bug starved it as collateral. A fix that placed only
    /// the pinned vCPU would satisfy a weaker test and still leave a CPU idle here.
    #[test]
    fn a_pinned_vcpu_does_not_stall_the_whole_scheduling_pass() {
        let mut sys = sched::System::new(1, 2, 2);
        let mut pol = Scheduler::new(1, 2, 10);
        sys.admit(0, 0).unwrap();
        sys.admit(0, 1).unwrap();
        // (0,0) may run only on pCPU 1; (0,0) is also the tie-break winner, so the old code
        // picked it first, aimed it at pCPU 0, and gave up when the mechanism said no.
        sys.set_affinity(0, 0, 0b10).unwrap();

        pol.advance(&mut sys, 0);

        assert_eq!(
            sys.occupant(1),
            Some((0, 0)),
            "the pinned vCPU takes its own CPU"
        );
        assert_eq!(
            sys.occupant(0),
            Some((0, 1)),
            "and the unpinned one is not starved with it"
        );
        assert_eq!(sys.busy_pcpus(), 2);
    }

    /// A vCPU whose mask admits no CPU at all is `Runnable` and legitimately unplaceable — so
    /// work conservation must be read as "no idle CPU that some waiter *may use*", and the policy
    /// must still place everyone else rather than stalling on it.
    #[test]
    fn an_unplaceable_vcpu_does_not_block_the_others() {
        let mut sys = sched::System::new(1, 2, 1);
        let mut pol = Scheduler::new(1, 2, 10);
        sys.admit(0, 0).unwrap();
        sys.admit(0, 1).unwrap();
        sys.set_affinity(0, 0, 0).unwrap(); // admits nothing

        pol.advance(&mut sys, 0);

        assert_eq!(sys.occupant(0), Some((0, 1)));
        assert_eq!(sys.state_of(0, 0), Some(RunState::Runnable));
    }

    /// Rule 2's half: a runner past its quantum is evicted only for a waiter that could actually
    /// take *its* CPU. Every pCPU is occupied here, so rule 1 cannot fire and the preemption path
    /// is genuinely the one under test.
    ///
    /// ★ The victim the old rule would pick is deliberately the *wrong* one. `A` on pCPU 0 is the
    /// least deserving runner (service 20 at weight 1) and so the globally best eviction
    /// candidate; `B` on pCPU 1 is far more deserving (service 20 at weight 100). The waiter `W`
    /// is more deserving than both — but it is pinned to pCPU 1. Choosing `A` would free a CPU
    /// `W` may not use, leaving it idle and `W` still waiting.
    #[test]
    fn a_runner_is_evicted_only_from_a_cpu_the_waiter_can_take() {
        let mut sys = sched::System::new(1, 3, 2);
        let mut pol = Scheduler::new(1, 3, 10);
        pol.set_weight(0, 1, 100); // B is heavily weighted, so its share stays tiny

        sys.admit(0, 0).unwrap();
        sys.run(0, 0, 0, 0).unwrap(); // A on pCPU 0
        sys.admit(0, 1).unwrap();
        sys.run(0, 1, 1, 0).unwrap(); // B on pCPU 1
        sys.admit(0, 2).unwrap(); // W waits, service 0
        sys.set_affinity(0, 2, 0b10).unwrap(); // ...and only pCPU 1 will have it

        // At t=20 both runners are past the quantum of 10, and both CPUs are busy.
        assert_eq!(
            pol.next(&sys, 20),
            Decision::Preempt {
                dom: 0,
                vcpu: 1,
                pcpu: 1
            },
            "the evicted runner must be the one on the CPU the waiter is affine to, \
             not the globally least-deserving one"
        );
    }

    #[test]
    fn advance_terminates_and_leaves_the_mechanism_consistent() {
        let (mut sys, mut pol) = setup(0); // quantum 0: maximally eager to preempt
        for d in 0..2u16 {
            for v in 0..2u32 {
                sys.admit(d, v).unwrap();
            }
        }
        // Even with quantum 0 and more vCPUs than CPUs, advance reaches a fixpoint and
        // the mechanism stays consistent.
        let enacted = pol.advance(&mut sys, 50);
        assert!(enacted >= 1);
        assert!(sys.invariants_hold());
        assert_eq!(sys.busy_pcpus(), 1, "the single CPU ends up occupied");
    }
}
