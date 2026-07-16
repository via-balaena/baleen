// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Fuzz the event-channel state machine.
//!
//! The input byte stream is decoded into a sequence of operations over a small
//! fixed system, and after *every* transition the whole-system invariants are
//! checked — reciprocity, no signals on free ports, VIRQ uniqueness, no ghost
//! domains. The transition surface is pure (no VM, no hardware), so libFuzzer
//! explores interleavings of bind/close/send at millions of exec/sec. The seeded
//! mirror in `hv-sim` (`run_evtchn`) makes the same property a deterministic test.
//!
//! Run it (needs nightly + `cargo install cargo-fuzz`):
//!
//! ```sh
//! cd hv-fuzz && cargo +nightly fuzz run evtchn
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use hv_core::evtchn::System;

const DOMAINS: usize = 3;
const PORTS: usize = 8;

fuzz_target!(|data: &[u8]| {
    let mut sys = System::new(DOMAINS, PORTS);
    let mut bytes = data.iter().copied();

    // Each op is one opcode byte plus up to three operand bytes.
    while let Some(op) = bytes.next() {
        let dom = (u16::from(bytes.next().unwrap_or(0))) % DOMAINS as u16;
        let a = bytes.next().unwrap_or(0);
        let b = bytes.next().unwrap_or(0);
        let port = u32::from(a) % PORTS as u32;

        match op % 8 {
            0 => {
                let _ = sys.alloc_unbound(dom, u16::from(a) % DOMAINS as u16);
            }
            1 => {
                let _ = sys.bind_interdomain(dom, u16::from(a) % DOMAINS as u16, u32::from(b) % PORTS as u32);
            }
            2 => {
                let _ = sys.bind_virq(dom, u32::from(a) % 2, b % 4);
            }
            3 => {
                let _ = sys.bind_ipi(dom, u32::from(a) % 2);
            }
            4 => {
                let _ = sys.close(dom, port);
            }
            5 => {
                let _ = sys.send(dom, port);
            }
            6 => {
                let _ = if b & 1 == 0 {
                    sys.mask(dom, port)
                } else {
                    sys.unmask(dom, port)
                };
            }
            _ => {
                let _ = sys.consume(dom, port);
            }
        }

        // The property: no reachable sequence of operations ever leaves the system
        // inconsistent. `invariants_hold` is evaluated regardless of build profile.
        assert!(
            sys.invariants_hold(),
            "event-channel invariant violated: {:?}",
            sys.first_violation()
        );
    }
});
