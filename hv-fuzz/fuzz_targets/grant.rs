// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Fuzz the grant-table state machine.
//!
//! The input byte stream is decoded into a sequence of grant/end/map/unmap/copy
//! operations over a small fixed system; live handles are tracked so unmaps target
//! real mappings. After every transition the whole-system invariants are checked —
//! refcount consistency, read-only integrity, grantee identity, and above all that
//! no mapping is ever left dangling (the cross-domain use-after-free this module
//! exists to prevent). The seeded mirror in `hv-sim` (`run_grant`) makes the same
//! property a deterministic test.
//!
//! Run it (needs nightly + `cargo install cargo-fuzz`):
//!
//! ```sh
//! cd hv-fuzz && cargo +nightly fuzz run grant
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use hv_core::grant::System;

const DOMAINS: usize = 3;
const ENTRIES: usize = 6;

fuzz_target!(|data: &[u8]| {
    let mut sys = System::new(DOMAINS, ENTRIES);
    let mut handles: Vec<(u16, u32)> = Vec::new();
    let mut bytes = data.iter().copied();

    while let Some(op) = bytes.next() {
        let dom = (u16::from(bytes.next().unwrap_or(0))) % DOMAINS as u16;
        let a = bytes.next().unwrap_or(0);
        let b = bytes.next().unwrap_or(0);
        let gref = u32::from(a) % ENTRIES as u32;
        let grantee = u16::from(b) % DOMAINS as u16;

        match op % 6 {
            0 => {
                let _ = sys.grant_access(dom, gref, grantee, u32::from(a), b & 1 == 0);
            }
            1 => {
                let _ = sys.end_access(dom, gref);
            }
            2 | 5 => {
                if let Ok(h) = sys.map(grantee, dom, gref, a & 1 == 0) {
                    handles.push((grantee, h));
                }
            }
            3 => {
                if !handles.is_empty() {
                    let (g, h) = handles.swap_remove(usize::from(a) % handles.len());
                    let _ = sys.unmap(g, h);
                }
            }
            _ => {
                let _ = sys.copy(grantee, dom, gref, a & 1 == 0);
            }
        }

        assert!(
            sys.invariants_hold(),
            "grant-table invariant violated: {:?}",
            sys.first_violation()
        );
    }
});
