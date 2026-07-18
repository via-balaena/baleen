// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

// Teach rustc that `cfg(kani)` is an expected configuration, so the `#[cfg(kani)]`-gated
// preservation proofs in `src/lib.rs` do not trip the `unexpected_cfgs` lint under a normal
// (non-Kani) build. The `kani` cfg itself is set by the `cargo kani` driver when it compiles
// the harnesses; this only declares it known.
fn main() {
    println!("cargo::rustc-check-cfg=cfg(kani)");
}
