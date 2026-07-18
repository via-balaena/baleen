// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Pass the bare-metal linker script to the linker. Done from `build.rs` (rather than a
//! `.cargo/config.toml` `rustflags`) so it applies regardless of the working directory the crate
//! is built from — `cargo xtask qemu` builds it from the repo root via `--manifest-path`.

fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:rustc-link-arg=-T{dir}/linker.ld");
    println!("cargo:rerun-if-changed=linker.ld");
}
