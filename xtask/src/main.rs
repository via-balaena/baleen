// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Baleen's task runner. Invoke as `cargo xtask <task>` (see `.cargo/config.toml`).
//!
//! Deliberately tiny for M1 — it grows to cover `hv-metal` cross-builds and the
//! `hv-fuzz` targets as those milestones land.

use std::process::{exit, Command};

fn main() {
    let task = std::env::args().nth(1).unwrap_or_default();
    let ok = match task.as_str() {
        "test" => run("cargo", &["test", "--workspace"]),
        "check" => run("cargo", &["check", "--workspace"]),
        "doc" => doc(),
        // Metal (M3): build `hv-metal` for the bare-metal target and boot it under QEMU.
        // `qemu` runs it interactively (dev); `qemu-test` runs the headless boot smoke-test the
        // CI loop asserts on. `hv-metal` is a standalone crate excluded from the workspace, so it
        // is built via `--manifest-path` with the bare-metal `--target`.
        "qemu" => {
            metal_build()
                && run(
                    "qemu-system-aarch64",
                    &[
                        "-M",
                        "virt,virtualization=on",
                        "-cpu",
                        "max",
                        "-nographic",
                        // No NIC: the default virt network device pulls a PXE romfile
                        // (`efi-virtio.rom`) some QEMU packages don't ship, and Arc 0 needs no
                        // networking. Keeps the boot deterministic across QEMU builds.
                        "-net",
                        "none",
                        "-kernel",
                        METAL_BIN,
                    ],
                )
        }
        "qemu-test" => run("bash", &["hv-metal/boot-test.sh"]),
        "ci" => {
            run("cargo", &["fmt", "--all", "--", "--check"])
                && run(
                    "cargo",
                    &[
                        "clippy",
                        "--workspace",
                        "--all-targets",
                        "--",
                        "-D",
                        "warnings",
                    ],
                )
                && run("cargo", &["test", "--workspace"])
                && doc()
        }
        other => {
            if !other.is_empty() {
                eprintln!("xtask: unknown task {other:?}\n");
            }
            eprintln!(
                "usage: cargo xtask <task>\n  \
                 test   run the workspace test suite\n  \
                 check  type-check the workspace\n  \
                 doc    build docs, denying broken links\n  \
                 ci     fmt --check, clippy -D warnings, test, then doc\n  \
                 qemu   boot hv-metal under QEMU (AArch64/EL2, interactive)\n  \
                 qemu-test  headless QEMU boot smoke-test (the metal CI check)"
            );
            exit(2);
        }
    };
    if !ok {
        exit(1);
    }
}

/// The bare-metal target `hv-metal` builds for, and the resulting binary path.
const METAL_TARGET: &str = "aarch64-unknown-none-softfloat";
const METAL_BIN: &str = "hv-metal/target/aarch64-unknown-none-softfloat/release/hv-metal";

/// Build `hv-metal` (a standalone, workspace-excluded crate) for the bare-metal target.
fn metal_build() -> bool {
    run(
        "cargo",
        &[
            "build",
            "--release",
            "--target",
            METAL_TARGET,
            "--manifest-path",
            "hv-metal/Cargo.toml",
        ],
    )
}

/// Build the docs with broken intra-doc links (and every other rustdoc lint)
/// treated as errors, so doc rot fails CI the same way a broken test does.
fn doc() -> bool {
    run_env(
        "cargo",
        &["doc", "--workspace", "--no-deps"],
        &[("RUSTDOCFLAGS", "-D warnings")],
    )
}

/// Run a command inheriting stdio, returning whether it succeeded.
fn run(program: &str, args: &[&str]) -> bool {
    run_env(program, args, &[])
}

/// Like [`run`], with extra environment variables set for the child.
fn run_env(program: &str, args: &[&str], env: &[(&str, &str)]) -> bool {
    eprintln!("$ {program} {}", args.join(" "));
    let mut cmd = Command::new(program);
    cmd.args(args);
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.status().map(|s| s.success()).unwrap_or(false)
}
