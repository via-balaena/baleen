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
                        "virt,virtualization=on,gic-version=3",
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
        // Metal (M5 Arc 5e): boot a REAL aarch64 Linux kernel as a single EL1 guest under hv-metal.
        // Kernel-gated — needs a kernel `Image` + initramfs in `$BALEEN_LINUX_DIR` (see the fn). Never
        // part of CI (the synthetic `qemu-test` is the CI check); this is the capstone demo.
        "qemu-linux" => qemu_linux(),
        "metal-lint" => metal_lint(),
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
                 qemu-test  headless QEMU boot smoke-test (the metal CI check)\n  \
                 metal-lint fmt --check + clippy -D warnings for hv-metal (both feature configs)"
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

// ─── M5 Arc 5e: the real-Linux capstone runner ──────────────────────────────────────────────────
// The guest-RAM load layout — MUST match `hv-metal/src/linux.rs`'s constants and `hv-metal/linux/
// guest.dts`. QEMU `-device loader` deposits the three blobs at these PAs before hv-metal boots.
const LINUX_KERNEL_ADDR: u64 = 0x4800_0000; // Image (also DTB /memory base)
const LINUX_DTB_ADDR: u64 = 0x4b00_0000; // DTB (hv-metal points guest x0 here)
const LINUX_INITRD_ADDR: u64 = 0x4c00_0000; // initramfs (DTB /chosen linux,initrd-*)

/// Boot a real aarch64 Linux kernel under hv-metal (M5 Arc 5e). Builds hv-metal `--features
/// real-linux`, compiles the guest DTB (patching `initrd-end` to the initramfs size), and launches
/// QEMU with the kernel `Image` + initramfs + DTB loaded into guest RAM via `-device loader`.
///
/// Kernel-gated: the `Image` and `initramfs` come from `$BALEEN_LINUX_DIR` (default
/// `~/forge/baleen-metal-linux/alpine`), holding `Image` (raw arm64 kernel) and `custom-initramfs.gz`.
fn qemu_linux() -> bool {
    use std::path::PathBuf;

    let dir = std::env::var("BALEEN_LINUX_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/forge/baleen-metal-linux/alpine")
    });
    let dir = PathBuf::from(dir);
    let image = dir.join("Image");
    let initrd = dir.join("custom-initramfs.gz");

    for (what, p) in [("kernel Image", &image), ("initramfs", &initrd)] {
        if !p.exists() {
            eprintln!(
                "xtask qemu-linux: missing {what} at {}\n  \
                 This target is kernel-gated: set $BALEEN_LINUX_DIR to a dir containing a raw arm64 \
                 `Image` and `custom-initramfs.gz` (see docs/ARC-5-M5-GUEST-INTERFACE.md).",
                p.display()
            );
            return false;
        }
    }

    // Compile the DTB, patching linux,initrd-end = initrd-start + initramfs size.
    let dts = match std::fs::read_to_string("hv-metal/linux/guest.dts") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xtask qemu-linux: cannot read hv-metal/linux/guest.dts: {e}");
            return false;
        }
    };
    let initrd_size = std::fs::metadata(&initrd).map(|m| m.len()).unwrap_or(0);
    let initrd_end = LINUX_INITRD_ADDR + initrd_size;
    let patched = dts.replace(
        &format!("linux,initrd-end = <0x{LINUX_INITRD_ADDR:x}>;"),
        &format!("linux,initrd-end = <0x{initrd_end:x}>;"),
    );
    let dts_out = dir.join("guest.patched.dts");
    let dtb_out = dir.join("guest.dtb");
    if let Err(e) = std::fs::write(&dts_out, patched) {
        eprintln!("xtask qemu-linux: cannot write {}: {e}", dts_out.display());
        return false;
    }
    if !run(
        "dtc",
        &[
            "-I",
            "dts",
            "-O",
            "dtb",
            dts_out.to_str().unwrap(),
            "-o",
            dtb_out.to_str().unwrap(),
        ],
    ) {
        eprintln!("xtask qemu-linux: dtc failed to compile the guest DTB");
        return false;
    }

    if !metal_build_linux() {
        return false;
    }

    // `-device loader,file=…,addr=…,force-raw=on` deposits each blob at its guest PA before the
    // `-kernel` (hv-metal) boots at EL2; hv-metal then erets into the kernel with x0 = the DTB.
    let loader = |file: &std::path::Path, addr: u64| {
        format!(
            "loader,file={},addr=0x{addr:x},force-raw=on",
            file.display()
        )
    };
    let args: Vec<String> = vec![
        "-M".into(),
        "virt,virtualization=on,gic-version=3".into(),
        // A stable ARMv8.0 baseline for the guest — NOT `-cpu max`. `max` advertises bleeding-edge
        // features (S1PIE, SME, GCS, pointer-auth) whose EL1 use traps to EL2 for the hypervisor to
        // enable (HCRX_EL2 …); our minimal EL2 doesn't, so the kernel traps on `PIRE0_EL1` early.
        // `cortex-a72` exposes only what hv-metal actually virtualizes (GICv3, arch timer, PSCI,
        // Stage-2), so an unmodified kernel boots without needing exotic-feature enablement at EL2.
        "-cpu".into(),
        "cortex-a72".into(),
        "-smp".into(),
        "1".into(),
        "-m".into(),
        "1024".into(),
        "-nographic".into(),
        "-net".into(),
        "none".into(),
        // Semihosting: hv-metal's SYSTEM_OFF handler issues a semihosting SYS_EXIT so QEMU exits
        // cleanly when the guest powers off (instead of parking until a timeout).
        "-semihosting".into(),
        "-kernel".into(),
        METAL_BIN.into(),
        "-device".into(),
        loader(&image, LINUX_KERNEL_ADDR),
        "-device".into(),
        loader(&dtb_out, LINUX_DTB_ADDR),
        "-device".into(),
        loader(&initrd, LINUX_INITRD_ADDR),
    ];
    let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run("qemu-system-aarch64", &argv)
}

/// Build `hv-metal` for the bare-metal target with `real-linux` + `selftest` (M5 Arc 5e/6b).
fn metal_build_linux() -> bool {
    run(
        "cargo",
        &[
            "build",
            "--release",
            "--target",
            METAL_TARGET,
            "--manifest-path",
            "hv-metal/Cargo.toml",
            "--features",
            // `selftest` too, so the Linux path runs `verify_encoding` on its REAL emitted tables:
            // 448 super-span blocks plus the device window read back and decoded, every other slot
            // asserted dead. Without it the one real guest's emission would be the only one not
            // verified at runtime (M5 Arc 6b).
            "real-linux,selftest",
        ],
    )
}

/// Lint `hv-metal` — fmt `--check` + clippy `-D warnings` on the bare-metal target, for BOTH
/// feature configs (default and `selftest`). `hv-metal` is excluded from the workspace, so
/// `cargo xtask ci`'s workspace-scoped fmt/clippy never touch it — yet it is the ONE crate that
/// carries `unsafe`, so it must stay under the same `-D warnings` bar. The `metal boot (QEMU)` CI
/// job runs this so the gate is enforced (single source of truth: CI calls this task).
///
/// Note: no `--all-targets` — a `#![no_std] #![no_main]` bare-metal bin has no buildable `test`
/// target (the test harness needs `std`), so `--all-targets` would fail to compile it.
fn metal_lint() -> bool {
    run(
        "cargo",
        &[
            "fmt",
            "--manifest-path",
            "hv-metal/Cargo.toml",
            "--",
            "--check",
        ],
    ) && metal_clippy(&[])
        && metal_clippy(&["--features", "selftest"])
}

/// Run clippy over `hv-metal` for the bare-metal target with `extra` cargo args, denying warnings.
fn metal_clippy(extra: &[&str]) -> bool {
    let mut args = vec![
        "clippy",
        "--manifest-path",
        "hv-metal/Cargo.toml",
        "--target",
        METAL_TARGET,
    ];
    args.extend_from_slice(extra);
    args.extend_from_slice(&["--", "-D", "warnings"]);
    run("cargo", &args)
}

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
