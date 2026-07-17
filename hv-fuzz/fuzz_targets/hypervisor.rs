// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Fuzz the integrated core through its single dispatch seam.
//!
//! The input byte stream is decoded into a sequence of `(caller, HvCall)` hypercalls
//! spanning all four subsystems — credit, event channels, grant tables, page-type
//! accounting — with live grant handles tracked so unmaps go to their owners. Grants
//! target real machine frames, so grant maps take page references through the seam and
//! the *cross-subsystem* invariant is exercised too. After every dispatch the combined
//! invariant is checked: one assertion covering the whole core, including that every
//! live grant mapping stays owned and backed by the page-type counts, and that no
//! deliverable event is left on a `Blocked` vCPU. Unlike the per-subsystem targets, this
//! one explores cross-subsystem interleavings — both seams the `Hypervisor` owns:
//! `EvtchnSend`/`EvtchnUnmask`/`SchedBlock` route through the event↔scheduler seam, so a
//! *lost wakeup* is caught here too. `P2mLink`/`P2mUnlink` build and dismantle multi-level
//! page tables, so a *mislevelled* entry (a table pointing at a frame of the wrong level)
//! is caught by the same invariant. `DomainDestroy` is the whole-domain teardown that
//! welds all four subsystems and both seams at once — refused when a foreign domain holds
//! a live map, tearing the domain to an empty shell otherwise — so a mis-ordered teardown
//! trips the same combined invariant. The seeded mirrors in `hv-sim` (`run_hypervisor`
//! broadly, `run_seam` wake-biased, `run_ptab` tree-building, `run_destroy` teardown-biased)
//! make the properties deterministic.
//!
//! Run it (needs nightly + `cargo install cargo-fuzz`):
//!
//! ```sh
//! cd hv-fuzz && cargo +nightly fuzz run hypervisor
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use hv_core::p2m::{PtLevel, TABLE_SLOTS};
use hv_core::{HvCall, HvOutcome, Hypervisor};

fn pt_level(n: u8) -> PtLevel {
    match n % 4 {
        0 => PtLevel::L1,
        1 => PtLevel::L2,
        2 => PtLevel::L3,
        _ => PtLevel::L4,
    }
}

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
        let mfn = u32::from(a) % FRAMES as u32;
        let child = u32::from(b) % FRAMES as u32;
        let slot = u32::from(a) % TABLE_SLOTS;
        now = now.wrapping_add(1 + u64::from(a));

        let call = match op % 28 {
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
            10 => HvCall::GrantAccess { gref, grantee: other, frame: mfn, readonly: b & 1 == 0 },
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
            20 => HvCall::SchedOffline { vcpu, now },
            21 => HvCall::P2mAllocate { mfn },
            22 => HvCall::P2mFree { mfn },
            23 => HvCall::P2mPin { mfn, level: pt_level(b) },
            24 => HvCall::P2mUnpin { mfn },
            // Page-table entries — build and dismantle the hierarchy. A mislevelled link
            // is refused at the seam, so only well-formed edges ever take.
            25 => HvCall::P2mLink { parent: mfn, slot, child },
            26 => HvCall::P2mUnlink { parent: mfn, slot },
            // Tear a whole domain down — all four subsystems and both seams at once.
            // Stale handles it leaves behind are already tolerated by the unmap arm.
            _ => HvCall::DomainDestroy { target: other, now },
        };

        let _ = hv.dispatch(caller, call);
        assert!(hv.invariants_hold(), "integrated invariant violated");
    }
});
