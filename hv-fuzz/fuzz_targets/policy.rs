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

/// Whether a physical CPU is idle while a vCPU is runnable — a work-conservation
/// breach.
fn idle_cpu_with_waiter(sys: &System) -> bool {
    let idle = (0..sys.pcpu_count() as u32).any(|p| sys.occupant(p).is_none());
    idle && (0..sys.domain_count() as u16).any(|d| {
        (0..sys.vcpu_count(d) as u32).any(|v| sys.state_of(d, v) == Some(RunState::Runnable))
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

        // Only availability changes here; placing vCPUs on CPUs is the policy's job.
        match op % 4 {
            0 => {
                let _ = sys.admit(dom, vcpu);
            }
            1 => {
                let _ = sys.block(dom, vcpu, now);
            }
            2 => {
                let _ = sys.wake(dom, vcpu);
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
