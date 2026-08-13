// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Fuzz the scheduling policy driving the mechanism.
//!
//! The input byte stream churns vCPU availability (admit/block/wake/offline) while a
//! monotonic clock advances, and after every churn the policy is driven to a fixpoint
//! with `advance`. Two properties are asserted after each step: the mechanism's own
//! invariant (pCPU exclusivity) still holds — the policy enacts only through public
//! transitions, so it must — and the policy is *work-conserving*: it never leaves a
//! physical CPU idle while a vCPU is runnable. The seeded mirror in `hv-sim`
//! (`run_policy`) makes the same properties deterministic tests.
//!
//! Run it (needs nightly + `cargo install cargo-fuzz`):
//!
//! ```sh
//! cd hv-fuzz && cargo +nightly fuzz run policy
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use hv_core::policy::Scheduler;
use hv_core::sched::{RunState, System};

const DOMAINS: usize = 2;
const VCPUS: usize = 3;
const PCPUS: usize = 2;

/// Whether a physical CPU is idle while a vCPU that **may use it** is runnable — a
/// work-conservation breach.
///
/// ⚠ The affinity clause is required, not a softening: a vCPU whose mask excludes every free CPU
/// is `Runnable` and legitimately unplaceable, so the free-CPU and the waiter must be paired
/// rather than chosen independently. See the same predicate in `hv-sim`'s `scenario.rs`.
fn idle_cpu_with_waiter(sys: &System) -> bool {
    (0..sys.pcpu_count() as u32).any(|p| {
        sys.occupant(p).is_none()
            && (0..sys.domain_count() as u16).any(|d| {
                (0..sys.vcpu_count(d) as u32).any(|v| {
                    sys.state_of(d, v) == Some(RunState::Runnable)
                        && sys.affinity_permits(d, v, p)
                })
            })
    })
}

fuzz_target!(|data: &[u8]| {
    let mut sys = System::new(DOMAINS, VCPUS, PCPUS);
    let mut pol = Scheduler::new(DOMAINS, VCPUS, 4);
    // A spread of weights so the fair-share comparison is exercised.
    for dom in 0..DOMAINS as u16 {
        for vcpu in 0..VCPUS as u32 {
            pol.set_weight(dom, vcpu, 1 + vcpu);
        }
    }

    let mut bytes = data.iter().copied();
    let mut now: u64 = 0;

    while let Some(op) = bytes.next() {
        let a = bytes.next().unwrap_or(0);
        let dom = (u16::from(a)) % DOMAINS as u16;
        let vcpu = (u32::from(a >> 2)) % VCPUS as u32;
        now = now.wrapping_add(1 + u64::from(a & 0x7));

        // Only availability and affinity change here; placing vCPUs on CPUs is the policy's job.
        //
        // ⚠⚠ The `set_affinity` arm is ㉘'s. Without it this alphabet was identical to
        // `hv-sim`'s `run_policy` churn, so the fuzzer and the seeded simulation were not two
        // independent tiers over the same property — they were one blind spot with two names,
        // and the work-conservation defect ㉘ fixed lived precisely on the axis neither moved.
        match op % 6 {
            0 => {
                let _ = sys.admit(dom, vcpu);
            }
            1 => {
                let _ = sys.block(dom, vcpu, now);
            }
            2 => {
                let _ = sys.wake(dom, vcpu);
            }
            3 => {
                // Includes the all-zero mask — a vCPU that may run nowhere is representable in
                // production, so the generator must be able to produce one.
                let _ = sys.set_affinity(dom, vcpu, u64::from(a) % (1u64 << PCPUS));
            }
            4 => {
                // ㉙ — the weight axis, fixed at init by every generator until now. The mid-run
                // change matters because wake-boost stores an offset derived from the weight, so
                // changing the weight afterwards leaves that offset against a stale divisor.
                pol.set_weight(dom, vcpu, 1 + u32::from(a) % 3);
            }
            _ => {
                let _ = sys.offline(dom, vcpu, now);
            }
        }

        pol.advance(&mut sys, now);

        assert!(
            sys.invariants_hold(),
            "mechanism invariant violated under policy: {:?}",
            sys.first_violation()
        );
        assert!(
            !idle_cpu_with_waiter(&sys),
            "policy left a CPU idle with a vCPU runnable"
        );
    }
});
