// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The scheduler — a pure, whole-system state machine
//!
//! The scheduler owns *where a vCPU is* and *how long it has run*: every domain's
//! virtual CPUs, their run states, and the occupancy of a fixed set of physical
//! CPUs, all in one [`System`]. It is the third generic hypervisor subsystem
//! alongside [`crate::evtchn`] and [`crate::grant`], and it is built to the same
//! discipline — whole-system state, one invariant checked on every transition.
//!
//! **Mechanism, not policy.** This module *moves* vCPUs between run states and
//! physical CPUs ([`System::run`], [`System::preempt`], [`System::block`], …); it
//! does not decide *which* runnable vCPU should get a CPU next. Fairness is policy,
//! not a safety property — a starved guest is a bug, but a *double-booked physical
//! CPU* is a catastrophe. Selection therefore lives above the core (a later policy
//! layer, ultimately a personality concern), exactly as wire formats do. What lives
//! here is the part with an invariant.
//!
//! **The headline invariant — pCPU exclusivity by reciprocity.** A physical CPU runs
//! at most one vCPU, and the two views of "who is running where" agree perfectly:
//!
//! > A vCPU is [`RunState::Running`]` { pcpu }` **if and only if** physical CPU
//! > `pcpu`'s occupant is exactly that vCPU.
//!
//! That biconditional is the scheduler's cousin of event-channel reciprocity: the
//! per-vCPU state and the per-pCPU occupancy table are two records of one fact, and a
//! transition that updates one without the other is caught the moment it happens.
//! Its violation is the scheduler's use-after-free — two vCPUs believing they own the
//! same registers, or a vCPU accounted as running on a CPU that has moved on.
//!
//! **Time enters through the fence.** The core owns no clock (see
//! [`hv_hal::TimeSource`]); the transitions that accrue run time take the current
//! [`hv_hal::Ticks`] as an argument, supplied by whoever holds the clock. A vCPU's
//! `runtime` grows only by closed on-CPU intervals and never decreases — the
//! scheduler's conservation property, the cousin of the credit account's.
//!
//! Provenance: the run-state lifecycle, the pCPU-exclusivity rule, and per-vCPU time
//! accounting are generic scheduler mechanics derived from general OS knowledge — not
//! `xen/`'s GPL scheduler implementation, and deliberately free of any specific
//! scheduling *policy* (credit/credit2/RTDS). See `CLEANROOM.md`.

extern crate alloc;

use alloc::vec::Vec;

use hv_hal::Ticks;

/// A domain identifier — an index into the [`System`]'s domain table.
pub type DomId = u16;
/// A virtual CPU identifier, scoped to a domain (an index into that domain's vCPU
/// table).
pub type Vcpu = u32;
/// A physical CPU identifier — an index into the system's pCPU occupancy table.
pub type Pcpu = u32;

/// What a vCPU *is doing*. Exactly one variant at any time — that totality is the
/// first thing the type buys us; every transition starts from a known state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// Not schedulable: never admitted, or taken back down. Holds no CPU.
    Offline,
    /// Wants a CPU and is waiting for one. Holds no CPU.
    Runnable,
    /// Currently executing on physical CPU `pcpu`. The occupancy table MUST name this
    /// vCPU back — that reciprocity is the headline invariant.
    Running { pcpu: Pcpu },
    /// Waiting on an event (a blocked hypercall, an unsignalled port). Holds no CPU
    /// and will not run until [`System::wake`] returns it to `Runnable`.
    Blocked,
}

/// One virtual CPU: its run state plus its accumulated on-CPU time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VirtualCpu {
    state: RunState,
    /// Total ticks this vCPU has spent `Running`, summed over closed intervals.
    /// Monotonic non-decreasing — the scheduler's conserved quantity.
    runtime: Ticks,
    /// When the current `Running` interval began. Meaningful only while `Running`;
    /// closed into `runtime` the moment the vCPU leaves a CPU.
    dispatched_at: Ticks,
}

impl VirtualCpu {
    const OFFLINE: Self = VirtualCpu {
        state: RunState::Offline,
        runtime: 0,
        dispatched_at: 0,
    };
}

/// One domain's fixed-size table of virtual CPUs.
#[derive(Clone)]
struct Domain {
    vcpus: Vec<VirtualCpu>,
}

/// The whole-system scheduler state: every domain's vCPUs plus the physical-CPU
/// occupancy table, in one place, so pCPU exclusivity is checkable after every
/// transition.
#[derive(Clone)]
pub struct System {
    domains: Vec<Domain>,
    /// Who is running on each physical CPU: `Some((dom, vcpu))` or idle. The
    /// authoritative peer of every [`RunState::Running`].
    pcpus: Vec<Option<(DomId, Vcpu)>>,
}

/// Why a transition was rejected. Rejections leave the system unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedError {
    /// The domain id is out of range.
    BadDomain,
    /// The vCPU id is out of range for its domain.
    BadVcpu,
    /// The physical CPU id is out of range.
    BadPcpu,
    /// The vCPU was not in a state this operation accepts (e.g. running an
    /// already-`Running` vCPU, or waking one that is not `Blocked`).
    WrongState,
    /// The target physical CPU is already running another vCPU.
    PcpuBusy,
}

/// A named invariant breach, carrying where it was found. Returned by
/// [`System::first_violation`] so the debug-time assert and the release-time property
/// tests report the *same* structured cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// A `Running` vCPU names a physical CPU that does not exist.
    RunningGhostPcpu { dom: usize, vcpu: usize },
    /// A `Running` vCPU's physical CPU does not name it back (broken reciprocity).
    OccupancyBroken { dom: usize, vcpu: usize },
    /// A physical CPU names an occupant that is not `Running` on it (broken
    /// reciprocity from the pCPU side).
    OccupantNotRunning { pcpu: usize },
    /// A physical CPU names an occupant whose domain/vCPU ids are out of range.
    OccupantGhost { pcpu: usize },
}

impl System {
    /// A system of `num_domains` domains, each with `vcpus_per_domain` offline vCPUs,
    /// over `num_pcpus` idle physical CPUs.
    pub fn new(num_domains: usize, vcpus_per_domain: usize, num_pcpus: usize) -> Self {
        let make_domain = || Domain {
            vcpus: (0..vcpus_per_domain).map(|_| VirtualCpu::OFFLINE).collect(),
        };
        System {
            domains: (0..num_domains).map(|_| make_domain()).collect(),
            pcpus: (0..num_pcpus).map(|_| None).collect(),
        }
    }

    // ─── transitions ─────────────────────────────────────────────────────────

    /// Bring an `Offline` vCPU online: `Offline` → `Runnable`. It now wants a CPU but
    /// has not been given one.
    pub fn admit(&mut self, dom: DomId, vcpu: Vcpu) -> Result<(), SchedError> {
        let v = self.vcpu_mut(dom, vcpu)?;
        if v.state != RunState::Offline {
            return Err(SchedError::WrongState);
        }
        v.state = RunState::Runnable;
        self.check_invariants();
        Ok(())
    }

    /// Dispatch a `Runnable` vCPU onto an idle physical CPU: `Runnable` →
    /// `Running { pcpu }`, marking `now` as the start of its on-CPU interval. Rejects
    /// a vCPU that is not `Runnable` and a `pcpu` already occupied.
    ///
    /// *Which* runnable vCPU and *which* idle pCPU is the caller's (policy's) choice;
    /// the core only enforces that the move is legal and updates both records
    /// together so reciprocity holds.
    pub fn run(
        &mut self,
        dom: DomId,
        vcpu: Vcpu,
        pcpu: Pcpu,
        now: Ticks,
    ) -> Result<(), SchedError> {
        // Validate everything before mutating, so a rejected dispatch is a true no-op.
        if pcpu as usize >= self.pcpus.len() {
            return Err(SchedError::BadPcpu);
        }
        if self.vcpu(dom, vcpu)?.state != RunState::Runnable {
            return Err(SchedError::WrongState);
        }
        if self.pcpus[pcpu as usize].is_some() {
            return Err(SchedError::PcpuBusy);
        }
        let v = self.vcpu_mut(dom, vcpu).unwrap();
        v.state = RunState::Running { pcpu };
        v.dispatched_at = now;
        self.pcpus[pcpu as usize] = Some((dom, vcpu));
        self.check_invariants();
        Ok(())
    }

    /// Take a `Running` vCPU back to `Runnable`, closing its on-CPU interval at `now`
    /// and freeing its physical CPU. The involuntary counterpart of a guest yield.
    pub fn preempt(&mut self, dom: DomId, vcpu: Vcpu, now: Ticks) -> Result<(), SchedError> {
        let pcpu = self.running_pcpu(dom, vcpu)?;
        self.account(dom, vcpu, now);
        self.pcpus[pcpu as usize] = None;
        self.vcpu_mut(dom, vcpu).unwrap().state = RunState::Runnable;
        self.check_invariants();
        Ok(())
    }

    /// Block a vCPU on an event: `Running` or `Runnable` → `Blocked`. If it was
    /// running, its interval is closed at `now` and its physical CPU freed. A blocked
    /// vCPU will not run again until [`Self::wake`].
    pub fn block(&mut self, dom: DomId, vcpu: Vcpu, now: Ticks) -> Result<(), SchedError> {
        match self.vcpu(dom, vcpu)?.state {
            RunState::Running { pcpu } => {
                self.account(dom, vcpu, now);
                self.pcpus[pcpu as usize] = None;
            }
            RunState::Runnable => {}
            RunState::Offline | RunState::Blocked => return Err(SchedError::WrongState),
        }
        self.vcpu_mut(dom, vcpu).unwrap().state = RunState::Blocked;
        self.check_invariants();
        Ok(())
    }

    /// Wake a `Blocked` vCPU: `Blocked` → `Runnable`. It wants a CPU again but does
    /// not get one here — that is a later [`Self::run`].
    pub fn wake(&mut self, dom: DomId, vcpu: Vcpu) -> Result<(), SchedError> {
        let v = self.vcpu_mut(dom, vcpu)?;
        if v.state != RunState::Blocked {
            return Err(SchedError::WrongState);
        }
        v.state = RunState::Runnable;
        self.check_invariants();
        Ok(())
    }

    /// Take a vCPU offline from any live state: `Runnable`/`Running`/`Blocked` →
    /// `Offline`. If it was running, its interval is closed at `now` and its physical
    /// CPU freed. Rejects an already-`Offline` vCPU so a caller cannot silently
    /// double-account or mistake a no-op for progress.
    pub fn offline(&mut self, dom: DomId, vcpu: Vcpu, now: Ticks) -> Result<(), SchedError> {
        match self.vcpu(dom, vcpu)?.state {
            RunState::Offline => return Err(SchedError::WrongState),
            RunState::Running { pcpu } => {
                self.account(dom, vcpu, now);
                self.pcpus[pcpu as usize] = None;
            }
            RunState::Runnable | RunState::Blocked => {}
        }
        self.vcpu_mut(dom, vcpu).unwrap().state = RunState::Offline;
        self.check_invariants();
        Ok(())
    }

    // ─── teardown ─────────────────────────────────────────────────────────────

    /// Take every vCPU `dom` owns offline — the scheduler step of tearing a domain
    /// down. Any physical CPU one of them occupies is freed and its on-CPU interval
    /// closed at `now`. Each [`Self::offline`] succeeds — only an already-`Offline`
    /// vCPU is rejected, and those are skipped.
    pub fn offline_all(&mut self, dom: DomId, now: Ticks) {
        for vcpu in 0..self.vcpu_count(dom) as Vcpu {
            if self.state_of(dom, vcpu) != Some(RunState::Offline) {
                let r = self.offline(dom, vcpu, now);
                debug_assert!(r.is_ok(), "offline_all failed on a live vCPU: {r:?}");
            }
        }
    }

    // ─── queries (the read side of the fence) ─────────────────────────────────

    /// The run state of a vCPU, if the ids are in range.
    pub fn state_of(&self, dom: DomId, vcpu: Vcpu) -> Option<RunState> {
        self.vcpu(dom, vcpu).ok().map(|v| v.state)
    }

    /// Whether a vCPU is currently `Running` (on any physical CPU).
    pub fn is_running(&self, dom: DomId, vcpu: Vcpu) -> bool {
        matches!(self.state_of(dom, vcpu), Some(RunState::Running { .. }))
    }

    /// A vCPU's accumulated on-CPU time in ticks, if the ids are in range. This
    /// counts only *closed* intervals — a currently-running vCPU's in-flight interval
    /// is not added until it leaves the CPU.
    pub fn runtime(&self, dom: DomId, vcpu: Vcpu) -> Option<Ticks> {
        self.vcpu(dom, vcpu).ok().map(|v| v.runtime)
    }

    /// When the current on-CPU interval began, for a vCPU that is `Running` now;
    /// `None` if it is not running (or its ids are bad). A policy layer above the
    /// mechanism uses this to measure how long the current interval has lasted — the
    /// quantum check — without keeping its own copy of dispatch times.
    pub fn on_cpu_since(&self, dom: DomId, vcpu: Vcpu) -> Option<Ticks> {
        let v = self.vcpu(dom, vcpu).ok()?;
        match v.state {
            RunState::Running { .. } => Some(v.dispatched_at),
            _ => None,
        }
    }

    /// Who is running on a physical CPU, if `pcpu` is in range and occupied.
    pub fn occupant(&self, pcpu: Pcpu) -> Option<(DomId, Vcpu)> {
        self.pcpus.get(pcpu as usize).copied().flatten()
    }

    /// Number of domains.
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Number of vCPUs in a domain (0 if the domain id is out of range).
    pub fn vcpu_count(&self, dom: DomId) -> usize {
        self.domain(dom).map(|d| d.vcpus.len()).unwrap_or(0)
    }

    /// Number of physical CPUs.
    pub fn pcpu_count(&self) -> usize {
        self.pcpus.len()
    }

    /// Number of physical CPUs currently running a vCPU.
    pub fn busy_pcpus(&self) -> usize {
        self.pcpus.iter().filter(|p| p.is_some()).count()
    }

    // ─── invariants ───────────────────────────────────────────────────────────

    /// The first invariant breach found, or `None` if the system is consistent. The
    /// single source of truth for correctness, used by both the debug-time assertion
    /// and release-mode property tests.
    pub fn first_violation(&self) -> Option<Violation> {
        // vCPU → pCPU: every `Running` vCPU names a real pCPU that names it back.
        for (d, dom) in self.domains.iter().enumerate() {
            for (c, vc) in dom.vcpus.iter().enumerate() {
                if let RunState::Running { pcpu } = vc.state {
                    match self.pcpus.get(pcpu as usize) {
                        None => return Some(Violation::RunningGhostPcpu { dom: d, vcpu: c }),
                        Some(occ) => {
                            let reciprocal = *occ == Some((d as DomId, c as Vcpu));
                            if !reciprocal {
                                return Some(Violation::OccupancyBroken { dom: d, vcpu: c });
                            }
                        }
                    }
                }
            }
        }
        // pCPU → vCPU: every occupied pCPU names a real vCPU that is `Running` on it.
        for (p, occ) in self.pcpus.iter().enumerate() {
            if let Some((dom, vcpu)) = *occ {
                match self.vcpu(dom, vcpu) {
                    Err(_) => return Some(Violation::OccupantGhost { pcpu: p }),
                    Ok(vc) => {
                        if vc.state != (RunState::Running { pcpu: p as Pcpu }) {
                            return Some(Violation::OccupantNotRunning { pcpu: p });
                        }
                    }
                }
            }
        }
        None
    }

    /// Whether every invariant holds. Always evaluated (unlike the debug assert), so
    /// tests can assert it in release builds too.
    pub fn invariants_hold(&self) -> bool {
        self.first_violation().is_none()
    }

    /// Assert the invariants — compiled out in release, so it is free on the metal yet
    /// hit by every seeded interleaving under test.
    fn check_invariants(&self) {
        debug_assert!(
            self.first_violation().is_none(),
            "scheduler invariant violated: {:?}",
            self.first_violation()
        );
    }

    // ─── internals ────────────────────────────────────────────────────────────

    /// Close the current on-CPU interval into `runtime`. `now` is the metal's clock;
    /// a clock that ran backwards since dispatch would under-count, so the delta is
    /// saturating rather than allowed to wrap — the accounting stays monotonic even
    /// if the time source misbehaves.
    fn account(&mut self, dom: DomId, vcpu: Vcpu, now: Ticks) {
        let v = self.vcpu_mut(dom, vcpu).unwrap();
        let delta = now.saturating_sub(v.dispatched_at);
        v.runtime = v.runtime.saturating_add(delta);
    }

    /// The physical CPU a vCPU is `Running` on, or the appropriate error if it is not
    /// running (or its ids are bad).
    fn running_pcpu(&self, dom: DomId, vcpu: Vcpu) -> Result<Pcpu, SchedError> {
        match self.vcpu(dom, vcpu)?.state {
            RunState::Running { pcpu } => Ok(pcpu),
            _ => Err(SchedError::WrongState),
        }
    }

    fn domain(&self, dom: DomId) -> Result<&Domain, SchedError> {
        self.domains.get(dom as usize).ok_or(SchedError::BadDomain)
    }

    fn domain_mut(&mut self, dom: DomId) -> Result<&mut Domain, SchedError> {
        self.domains
            .get_mut(dom as usize)
            .ok_or(SchedError::BadDomain)
    }

    fn vcpu(&self, dom: DomId, vcpu: Vcpu) -> Result<&VirtualCpu, SchedError> {
        self.domain(dom)?
            .vcpus
            .get(vcpu as usize)
            .ok_or(SchedError::BadVcpu)
    }

    fn vcpu_mut(&mut self, dom: DomId, vcpu: Vcpu) -> Result<&mut VirtualCpu, SchedError> {
        self.domain_mut(dom)?
            .vcpus
            .get_mut(vcpu as usize)
            .ok_or(SchedError::BadVcpu)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A 3-domain system, 2 vCPUs each, over 2 physical CPUs — enough to exercise
    // every transition and to contend for CPUs.
    fn sys() -> System {
        System::new(3, 2, 2)
    }

    #[test]
    fn admit_then_run_occupies_a_pcpu_reciprocally() {
        let mut s = sys();
        s.admit(0, 0).unwrap();
        s.run(0, 0, 1, 100).unwrap();
        assert_eq!(s.state_of(0, 0), Some(RunState::Running { pcpu: 1 }));
        assert_eq!(s.occupant(1), Some((0, 0)));
        assert!(s.is_running(0, 0));
        assert!(s.invariants_hold());
    }

    #[test]
    fn cannot_run_a_vcpu_that_was_not_admitted() {
        let mut s = sys();
        // Still Offline.
        assert_eq!(s.run(0, 0, 0, 0), Err(SchedError::WrongState));
        assert_eq!(s.occupant(0), None);
    }

    #[test]
    fn a_pcpu_runs_at_most_one_vcpu() {
        let mut s = sys();
        s.admit(0, 0).unwrap();
        s.admit(1, 0).unwrap();
        s.run(0, 0, 0, 0).unwrap();
        // The second vCPU cannot take an occupied CPU...
        assert_eq!(s.run(1, 0, 0, 0), Err(SchedError::PcpuBusy));
        // ...and the loser is untouched: still Runnable, no CPU.
        assert_eq!(s.state_of(1, 0), Some(RunState::Runnable));
        // A free CPU is fine.
        assert!(s.run(1, 0, 1, 0).is_ok());
        assert!(s.invariants_hold());
    }

    #[test]
    fn preempt_frees_the_pcpu_and_accrues_runtime() {
        let mut s = sys();
        s.admit(0, 0).unwrap();
        s.run(0, 0, 0, 100).unwrap();
        s.preempt(0, 0, 130).unwrap();
        assert_eq!(s.state_of(0, 0), Some(RunState::Runnable));
        assert_eq!(s.occupant(0), None, "preempted CPU must be idle");
        assert_eq!(s.runtime(0, 0), Some(30));
        assert!(s.invariants_hold());
    }

    #[test]
    fn cannot_preempt_a_vcpu_that_is_not_running() {
        let mut s = sys();
        s.admit(0, 0).unwrap();
        assert_eq!(s.preempt(0, 0, 0), Err(SchedError::WrongState));
    }

    #[test]
    fn block_from_running_frees_the_cpu_then_wake_makes_runnable() {
        let mut s = sys();
        s.admit(0, 0).unwrap();
        s.run(0, 0, 0, 10).unwrap();
        s.block(0, 0, 25).unwrap();
        assert_eq!(s.state_of(0, 0), Some(RunState::Blocked));
        assert_eq!(s.occupant(0), None);
        assert_eq!(s.runtime(0, 0), Some(15));
        // A blocked vCPU cannot be run until it is woken.
        assert_eq!(s.run(0, 0, 0, 30), Err(SchedError::WrongState));
        s.wake(0, 0).unwrap();
        assert_eq!(s.state_of(0, 0), Some(RunState::Runnable));
        assert!(s.run(0, 0, 0, 30).is_ok());
    }

    #[test]
    fn block_from_runnable_holds_no_cpu() {
        let mut s = sys();
        s.admit(0, 0).unwrap();
        s.block(0, 0, 5).unwrap();
        assert_eq!(s.state_of(0, 0), Some(RunState::Blocked));
        assert_eq!(s.runtime(0, 0), Some(0), "never ran, so no runtime");
    }

    #[test]
    fn wake_only_applies_to_blocked() {
        let mut s = sys();
        s.admit(0, 0).unwrap();
        assert_eq!(s.wake(0, 0), Err(SchedError::WrongState)); // Runnable, not Blocked
    }

    #[test]
    fn offline_from_running_frees_the_cpu_and_is_refused_when_already_offline() {
        let mut s = sys();
        s.admit(0, 0).unwrap();
        s.run(0, 0, 1, 0).unwrap();
        s.offline(0, 0, 40).unwrap();
        assert_eq!(s.state_of(0, 0), Some(RunState::Offline));
        assert_eq!(s.occupant(1), None);
        assert_eq!(s.runtime(0, 0), Some(40));
        // Already offline — refused, not a silent no-op.
        assert_eq!(s.offline(0, 0, 50), Err(SchedError::WrongState));
    }

    #[test]
    fn runtime_accumulates_across_several_intervals() {
        let mut s = sys();
        s.admit(0, 0).unwrap();
        s.run(0, 0, 0, 100).unwrap();
        s.preempt(0, 0, 110).unwrap(); // +10
        s.run(0, 0, 0, 200).unwrap();
        s.preempt(0, 0, 225).unwrap(); // +25
        assert_eq!(s.runtime(0, 0), Some(35));
    }

    #[test]
    fn a_backwards_clock_never_decreases_runtime() {
        let mut s = sys();
        s.admit(0, 0).unwrap();
        s.run(0, 0, 0, 100).unwrap();
        // Time appears to go backwards between dispatch and deschedule.
        s.preempt(0, 0, 50).unwrap();
        assert_eq!(s.runtime(0, 0), Some(0), "saturating delta, not a wrap");
    }

    #[test]
    fn same_vcpu_can_migrate_between_pcpus() {
        let mut s = sys();
        s.admit(0, 0).unwrap();
        s.run(0, 0, 0, 0).unwrap();
        s.preempt(0, 0, 5).unwrap();
        s.run(0, 0, 1, 5).unwrap();
        assert_eq!(s.occupant(0), None);
        assert_eq!(s.occupant(1), Some((0, 0)));
        assert!(s.invariants_hold());
    }

    #[test]
    fn on_cpu_since_tracks_the_current_interval_only() {
        let mut s = sys();
        s.admit(0, 0).unwrap();
        assert_eq!(s.on_cpu_since(0, 0), None, "not running yet");
        s.run(0, 0, 0, 100).unwrap();
        assert_eq!(s.on_cpu_since(0, 0), Some(100));
        s.preempt(0, 0, 150).unwrap();
        assert_eq!(s.on_cpu_since(0, 0), None, "no longer running");
        // A fresh interval reports the new dispatch time, not the old one.
        s.run(0, 0, 1, 200).unwrap();
        assert_eq!(s.on_cpu_since(0, 0), Some(200));
    }

    #[test]
    fn offline_all_takes_down_every_vcpu_and_frees_their_pcpus() {
        let mut s = sys();
        // Domain 0: vCPU 0 running on pCPU 1, vCPU 1 merely runnable.
        s.admit(0, 0).unwrap();
        s.run(0, 0, 1, 100).unwrap();
        s.admit(0, 1).unwrap();
        // Domain 1 has a vCPU running on pCPU 0 that must survive domain 0's teardown.
        s.admit(1, 0).unwrap();
        s.run(1, 0, 0, 100).unwrap();

        s.offline_all(0, 160);
        assert_eq!(s.state_of(0, 0), Some(RunState::Offline));
        assert_eq!(s.state_of(0, 1), Some(RunState::Offline));
        assert_eq!(s.occupant(1), None, "domain 0's pCPU is freed");
        assert_eq!(s.runtime(0, 0), Some(60), "its interval was closed at now");
        // Domain 1 is untouched.
        assert_eq!(s.occupant(0), Some((1, 0)));
        assert_eq!(s.state_of(1, 0), Some(RunState::Running { pcpu: 0 }));
        assert!(s.invariants_hold());
    }

    #[test]
    fn bad_ids_are_rejected() {
        let mut s = sys();
        assert_eq!(s.admit(9, 0), Err(SchedError::BadDomain));
        assert_eq!(s.admit(0, 9), Err(SchedError::BadVcpu));
        s.admit(0, 0).unwrap();
        assert_eq!(s.run(0, 0, 9, 0), Err(SchedError::BadPcpu));
    }

    #[test]
    fn all_pcpus_busy_still_leaves_a_consistent_system() {
        let mut s = sys();
        s.admit(0, 0).unwrap();
        s.admit(1, 0).unwrap();
        s.run(0, 0, 0, 0).unwrap();
        s.run(1, 0, 1, 0).unwrap();
        assert_eq!(s.busy_pcpus(), 2);
        // A third runnable vCPU finds no free CPU.
        s.admit(2, 0).unwrap();
        assert_eq!(s.run(2, 0, 0, 0), Err(SchedError::PcpuBusy));
        assert_eq!(s.run(2, 0, 1, 0), Err(SchedError::PcpuBusy));
        assert!(s.invariants_hold());
    }
}
