// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Fuzz the scheduler state machine.
//!
//! The input byte stream is decoded into a sequence of admit/run/preempt/block/wake/
//! offline operations over a small fixed system, with a monotonically advancing clock
//! so time accounting is exercised too. After *every* transition the whole-system
//! invariant is checked — pCPU exclusivity and run-state/occupancy reciprocity. The
//! transition surface is pure (no VM, no hardware), so libFuzzer explores
//! interleavings of two vCPUs contending for one physical CPU at millions of
//! exec/sec. The seeded mirror in `hv-sim` (`run_sched`) makes the same property a
//! deterministic test.
//!
//! Run it (needs nightly + `cargo install cargo-fuzz`):
//!
//! ```sh
//! cd hv-fuzz && cargo +nightly fuzz run sched
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use hv_core::sched::System;

const DOMAINS: usize = 3;
const VCPUS: usize = 2;
const PCPUS: usize = 2;

fuzz_target!(|data: &[u8]| {
    let mut sys = System::new(DOMAINS, VCPUS, PCPUS);
    let mut bytes = data.iter().copied();
    // A clock cranked by the input, so every run/preempt interval spans a fuzzed gap.
    let mut now: u64 = 0;

    // Each op is one opcode byte plus up to three operand bytes.
    while let Some(op) = bytes.next() {
        let dom = (u16::from(bytes.next().unwrap_or(0))) % DOMAINS as u16;
        let a = bytes.next().unwrap_or(0);
        let b = bytes.next().unwrap_or(0);
        let vcpu = u32::from(a) % VCPUS as u32;
        let pcpu = u32::from(b) % PCPUS as u32;
        now = now.wrapping_add(1 + u64::from(a));

        match op % 6 {
            0 => {
                let _ = sys.admit(dom, vcpu);
            }
            1 => {
                let _ = sys.run(dom, vcpu, pcpu, now);
            }
            2 => {
                let _ = sys.preempt(dom, vcpu, now);
            }
            3 => {
                let _ = sys.block(dom, vcpu, now);
            }
            4 => {
                let _ = sys.wake(dom, vcpu);
            }
            _ => {
                let _ = sys.offline(dom, vcpu, now);
            }
        }

        // The property: no reachable sequence of operations ever leaves the system
        // inconsistent. `invariants_hold` is evaluated regardless of build profile.
        assert!(
            sys.invariants_hold(),
            "scheduler invariant violated: {:?}",
            sys.first_violation()
        );
    }
});
