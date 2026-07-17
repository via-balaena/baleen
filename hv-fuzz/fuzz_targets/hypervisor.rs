// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Fuzz the integrated core through its single dispatch seam.
//!
//! The input byte stream is decoded into a sequence of `(caller, HvCall)` hypercalls
//! spanning all three subsystems — credit, event channels, grant tables — with live
//! grant handles tracked so unmaps go to their owners. After every dispatch the
//! *combined* invariant is checked: one assertion covering the whole core. Unlike
//! the per-subsystem targets, this one explores cross-subsystem interleavings. The
//! seeded mirror in `hv-sim` (`run_hypervisor`) makes the property deterministic.
//!
//! Run it (needs nightly + `cargo install cargo-fuzz`):
//!
//! ```sh
//! cd hv-fuzz && cargo +nightly fuzz run hypervisor
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use hv_core::{HvCall, HvOutcome, Hypervisor};

const DOMAINS: usize = 3;
const PORTS: usize = 8;
const GRANTS: usize = 6;
const VCPUS: usize = 2;
const PCPUS: usize = 2;
const FRAMES: usize = 6;

fuzz_target!(|data: &[u8]| {
    let mut hv = Hypervisor::new(DOMAINS, PORTS, GRANTS, VCPUS, PCPUS, FRAMES);
    let mut handles: Vec<(u16, u32)> = Vec::new();
    let mut bytes = data.iter().copied();
    let mut now: u64 = 0;

    while let Some(op) = bytes.next() {
        let caller = (u16::from(bytes.next().unwrap_or(0))) % DOMAINS as u16;
        let a = bytes.next().unwrap_or(0);
        let b = bytes.next().unwrap_or(0);
        let port = u32::from(a) % PORTS as u32;
        let gref = u32::from(a) % GRANTS as u32;
        let other = u16::from(b) % DOMAINS as u16;
        let vcpu = u32::from(a) % VCPUS as u32;
        let pcpu = u32::from(b) % PCPUS as u32;
        now = now.wrapping_add(1 + u64::from(a));

        let call = match op % 21 {
            0 => HvCall::CreditGrant { amount: u32::from(a) },
            1 => HvCall::CreditSpend { amount: u32::from(a) },
            2 => HvCall::EvtchnAllocUnbound { remote: other },
            3 => HvCall::EvtchnBindInterdomain { remote: other, remote_port: u32::from(b) % PORTS as u32 },
            4 => HvCall::EvtchnBindVirq { vcpu: u32::from(a) % 2, virq: b % 4 },
            5 => HvCall::EvtchnBindIpi { vcpu: u32::from(a) % 2 },
            6 => HvCall::EvtchnClose { port },
            7 => HvCall::EvtchnSend { port },
            8 => HvCall::EvtchnMask { port },
            9 => HvCall::EvtchnConsume { port },
            10 => HvCall::GrantAccess { gref, grantee: other, frame: u64::from(a), readonly: b & 1 == 0 },
            11 => HvCall::GrantEndAccess { gref },
            12 => {
                if let Ok(HvOutcome::Handle(h)) =
                    hv.dispatch(caller, HvCall::GrantMap { grantor: other, gref, writable: a & 1 == 0 })
                {
                    handles.push((caller, h));
                }
                assert!(hv.invariants_hold(), "integrated invariant violated");
                continue;
            }
            13 => {
                if !handles.is_empty() {
                    let (owner, handle) = handles.swap_remove(usize::from(a) % handles.len());
                    let _ = hv.dispatch(owner, HvCall::GrantUnmap { handle });
                }
                assert!(hv.invariants_hold(), "integrated invariant violated");
                continue;
            }
            14 => HvCall::GrantCopy { grantor: other, gref, write: a & 1 == 0 },
            15 => HvCall::SchedAdmit { vcpu },
            16 => HvCall::SchedRun { vcpu, pcpu, now },
            17 => HvCall::SchedPreempt { vcpu, now },
            18 => HvCall::SchedBlock { vcpu, now },
            19 => HvCall::SchedWake { vcpu },
            _ => HvCall::SchedOffline { vcpu, now },
        };

        let _ = hv.dispatch(caller, call);
        assert!(hv.invariants_hold(), "integrated invariant violated");
    }
});
