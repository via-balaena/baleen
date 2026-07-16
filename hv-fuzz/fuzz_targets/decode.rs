// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Fuzz the hypercall decoder — the first pure seam.
//!
//! `Hypercall::decode` is a total function from `(nr, arg0)` to a typed call or an
//! error. With no VM in the loop, libFuzzer hammers it at millions of exec/sec.
//! This target pins the decoder's whole contract, so any future personality change
//! that breaks it is caught here (and in the stable mirror test in `hv-core`).
//!
//! Run it (needs nightly + `cargo install cargo-fuzz`):
//!
//! ```sh
//! cd hv-fuzz && cargo +nightly fuzz run decode
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

use hv_core::{HError, Hypercall, RawHypercall, NR_GRANT, NR_SPEND};

fuzz_target!(|data: &[u8]| {
    // Need 12 bytes: u32 nr + u64 arg0. Anything shorter is not an interesting input.
    if data.len() < 12 {
        return;
    }
    let nr = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let arg0 = u64::from_le_bytes(data[4..12].try_into().unwrap());

    check_decode_contract(nr, arg0);
});

/// The decoder's full contract, asserted. Kept as a free function so the exact same
/// checks run as a deterministic unit test on stable in `hv-core` — the fuzzer
/// explores the space, CI proves the property without nightly.
#[inline]
fn check_decode_contract(nr: u32, arg0: u64) {
    let fits_u32 = arg0 <= u64::from(u32::MAX);
    match Hypercall::decode(RawHypercall { nr, arg0 }) {
        // An accepted call must round-trip its fields exactly and match its number.
        Ok(Hypercall::Grant { amount }) => {
            assert_eq!(nr, NR_GRANT);
            assert_eq!(u64::from(amount), arg0);
        }
        Ok(Hypercall::Spend { amount }) => {
            assert_eq!(nr, NR_SPEND);
            assert_eq!(u64::from(amount), arg0);
        }
        // Rejection happens for exactly two reasons: unknown number, or an argument
        // that does not fit the u32 field. Nothing else may be rejected.
        Err(HError::BadHypercall) => {
            let known = nr == NR_GRANT || nr == NR_SPEND;
            assert!(!known || !fits_u32, "rejected a valid (nr={nr}, arg0={arg0})");
        }
        Err(other) => panic!("decode returned an unexpected error: {other:?}"),
    }
}
