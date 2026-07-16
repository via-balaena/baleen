<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# hv-fuzz

`cargo-fuzz` targets against `hv-core`'s pure seams. Because the core is a `no_std`
library with no VM in the loop, these run natively at millions of exec/sec.

This crate is **standalone** (its own empty `[workspace]`) and **excluded** from the
parent workspace, so the stable `cargo test --workspace` never pulls in nightly or
libFuzzer. Each target's contract is also mirrored as a deterministic unit test on
stable in the crate under test, so CI proves the property even without running the
fuzzer.

## Run

Needs nightly and the `cargo-fuzz` subcommand:

```sh
cargo install cargo-fuzz
cd hv-fuzz
cargo +nightly fuzz run decode          # fuzz the hypercall decoder
cargo +nightly fuzz list                # list targets
```

## Targets

| target   | seam under test                          | mirror test |
| -------- | ---------------------------------------- | ----------- |
| `decode` | `hv_core::Hypercall::decode` — the ABI decode seam | `hv-core` `decode_contract_holds_*` |

As the M2 event-channel state machine lands, its transition function becomes the
next target here.
