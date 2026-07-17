// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Fuzz the page-type accounting state machine.
//!
//! The input byte stream is decoded into a sequence of allocate/get/put/get_type/
//! put_type/pin/unpin/free operations over a small fixed frame table; live typed
//! references are tracked so put_type targets a type the frame actually holds. After
//! every transition
//! the whole-system invariants are checked — reference coherence, owner integrity, and
//! above all that no frame is ever referenced as writable and as a page table at once
//! (the type-confusion this module exists to prevent, the shape of Xen's `PGT_*`
//! typecount XSAs). The seeded mirror in `hv-sim` (`run_p2m`) makes the same property
//! a deterministic test.
//!
//! Run it (needs nightly + `cargo install cargo-fuzz`):
//!
//! ```sh
//! cd hv-fuzz && cargo +nightly fuzz run p2m
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use hv_core::p2m::{PageType, PtLevel, System};

const DOMAINS: usize = 3;
const FRAMES: usize = 6;

fn pt_level(n: u8) -> PtLevel {
    match n % 4 {
        0 => PtLevel::L1,
        1 => PtLevel::L2,
        2 => PtLevel::L3,
        _ => PtLevel::L4,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut sys = System::new(DOMAINS, FRAMES);
    let mut typed: Vec<(u32, PageType)> = Vec::new();
    let mut bytes = data.iter().copied();

    while let Some(op) = bytes.next() {
        let owner = (u16::from(bytes.next().unwrap_or(0))) % DOMAINS as u16;
        let a = bytes.next().unwrap_or(0);
        let mfn = u32::from(a) % FRAMES as u32;
        let ty = if a & 1 == 0 {
            PageType::Writable
        } else {
            PageType::PageTable(pt_level(a >> 1))
        };

        match op % 9 {
            0 => {
                let _ = sys.allocate(owner, mfn);
            }
            1 => {
                let _ = sys.get(mfn);
            }
            2 => {
                let _ = sys.put(mfn);
            }
            3 | 4 => {
                if sys.get_type(mfn, ty).is_ok() {
                    typed.push((mfn, ty));
                }
            }
            5 => {
                if !typed.is_empty() {
                    let (m, t) = typed.swap_remove(usize::from(a) % typed.len());
                    let _ = sys.put_type(m, t);
                }
            }
            6 => {
                let _ = sys.pin(owner, mfn, pt_level(a));
            }
            7 => {
                let _ = sys.unpin(owner, mfn);
            }
            _ => {
                let _ = sys.free(owner, mfn);
            }
        }

        assert!(
            sys.invariants_hold(),
            "page-type invariant violated: {:?}",
            sys.first_violation()
        );
    }
});
