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
        // Needs a kernel `Image` + initramfs in `$BALEEN_LINUX_DIR`, which `hv-metal/linux/
        // fetch-guest-image.sh` builds from checksum-pinned Alpine downloads.
        //   `qemu-linux`      the interactive demo (stdio inherited; you watch a kernel boot).
        //   `qemu-linux-test` the headless gate: same QEMU line, output captured, markers asserted.
        // Both go through ONE `linux_qemu_args` (design-lesson #14c) — the gate must not be able to
        // pass against a QEMU invocation the demo does not use.
        "qemu-linux" => qemu_linux(false),
        "qemu-linux-test" => qemu_linux(true),
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
                 qemu-linux      boot a REAL Linux kernel under hv-metal (interactive demo)\n  \
                 qemu-linux-test the same boot, headless, asserting its markers (a CI check)\n  \
                 metal-lint fmt --check + clippy -D warnings for hv-metal (all four feature configs)"
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
/// With `check` false this is the interactive demo: QEMU inherits stdio and you watch a kernel boot.
/// With `check` true it is the gate `.github/workflows/ci.yml`'s `real-linux boot (QEMU)` job runs —
/// the SAME QEMU line, with the output captured and [`LINUX_MARKERS`] / [`LINUX_FORBIDDEN`] asserted
/// against it. One derivation, so the gate cannot pass against a boot the demo does not perform.
///
/// The `Image` and `initramfs` come from `$BALEEN_LINUX_DIR` (default
/// `~/forge/baleen-metal-linux/alpine`); `hv-metal/linux/fetch-guest-image.sh` builds both from
/// checksum-pinned official Alpine downloads.
fn qemu_linux(check: bool) -> bool {
    use std::path::PathBuf;

    let task = if check {
        "qemu-linux-test"
    } else {
        "qemu-linux"
    };
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
                "xtask {task}: missing {what} at {}\n  \
                 Build the guest artifacts first:  hv-metal/linux/fetch-guest-image.sh\n  \
                 (or point $BALEEN_LINUX_DIR at a dir holding a raw arm64 `Image` and \
                 `custom-initramfs.gz` — see docs/ARC-5-M5-GUEST-INTERFACE.md).",
                p.display()
            );
            return false;
        }
    }

    // Compile the DTB, patching linux,initrd-end = initrd-start + initramfs size.
    let dts = match std::fs::read_to_string("hv-metal/linux/guest.dts") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xtask {task}: cannot read hv-metal/linux/guest.dts: {e}");
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
        eprintln!("xtask {task}: cannot write {}: {e}", dts_out.display());
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
        eprintln!("xtask {task}: dtc failed to compile the guest DTB");
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
    if !check {
        return run("qemu-system-aarch64", &argv);
    }
    boot_and_check_linux(&argv)
}

// ─── the real-Linux boot's assertions (⑬: the capstone becomes a re-runnable gate) ───────────────

/// Markers that MUST appear in the real-Linux boot. Each is a witness produced BY a mechanism rather
/// than a claim about one (design-lesson #24f), and the VALUES are load-bearing — do not loosen any
/// of these to a value-free substring, exactly as `hv-metal/boot-test.sh` says of `-> result=100`.
///
/// Why each one could have failed:
///
/// * **`linux model built — 448 super-span leaves …`** — `build_model_and_stage2` issues 448
///   `P2mAllocate`/`P2mLink` pairs plus 56 `P2mAllocate`/`P2mPin` through the real
///   `Hypervisor::dispatch`, halting on the first `Err`. The three numbers are the memory contract:
///   shrink `LINUX_RAM_END`, change the granule, or change the span the emitter picks, and they move.
/// * **`selftest: Stage-2 encoding verified …`** — `verify_encoding` re-decodes the descriptors the
///   proven emitter actually wrote for THIS guest (448 blocks + the 32 MiB device window) and asserts
///   every other slot is dead. The one real guest's emission is the one that would otherwise never be
///   checked at runtime (M5 Arc 6b).
/// * **`Machine model: baleen-metal-guest`** — a string that exists only in `hv-metal/linux/
///   guest.dts`, echoed by the kernel. The kernel can only print it by READING the DTB at
///   `0x4b00_0000` through the emitted Stage-2 map AND driving the PL011 in the pass-through device
///   window. Un-forgeable in the same way `ro=0x5eed` is on the synthetic path.
/// * **`node   0: [mem 0x0000000048000000-0x000000007fffffff]`** — THE MEMORY CONTRACT, in one
///   string. It is the kernel reporting the window it got from our DTB, and it must equal
///   `LINUX_RAM_BASE..LINUX_RAM_END` in `hv-metal/src/linux.rs` (what the emitter maps) and the
///   `-device loader` addresses above (where the blobs land). Four places that must agree; this is
///   the assertion that goes red when they stop agreeing.
/// * **`Linux version 6.18.`** — an unmodified upstream Alpine kernel, not a stub that prints
///   markers.
/// * **`linux PSCI FID 0x84000006 -> NOT_SUPPORTED`** — the kernel's `MIGRATE_INFO_TYPE` probe
///   trapped from EL1 to EL2 and hv-metal's handler serviced it. The HVC path is live and the kernel
///   continued past it.
/// * **`Run /init as init process` + `BALEEN-STEP0-OK` + `baleen-guest-ram: …`** — the kernel
///   unpacked OUR initramfs from `0x4c00_0000` and reached userspace, which then reports the RAM
///   window from INSIDE the guest (`/proc/iomem`) — the guest-side half of the memory contract.
/// * **`linux guest issued PSCI SYSTEM_OFF …`** — the whole round trip, and the reason the boot
///   terminates rather than parking: busybox `poweroff -f` -> the kernel's PSCI -> `HVC` -> EL2.
const LINUX_MARKERS: &[&str] = &[
    // hv-metal, before the guest runs.
    "baleen: M5 Arc 5e — booting a REAL aarch64 Linux kernel as a single EL1 guest",
    "baleen: linux model built — 448 super-span leaves (896 MiB of guest RAM) across 56 L2-pinned tables",
    "448 super-span 2 MiB block(s) emitted and decoded; device window 32 MiB",
    // The kernel, behind the proven emitter.
    "Linux version 6.18.",
    "Machine model: baleen-metal-guest",
    "node   0: [mem 0x0000000048000000-0x000000007fffffff]",
    "baleen: linux PSCI FID 0x84000006 -> NOT_SUPPORTED",
    "Run /init as init process",
    // Userspace, out of our initramfs.
    "########## BALEEN-STEP0-OK ##########",
    "baleen-guest-ram: 48000000-7fffffff:SystemRAM",
    // The round trip home.
    "baleen: linux guest issued PSCI SYSTEM_OFF — a real Linux kernel booted and shut down on hv-metal's EL2",
];

/// Strings that must NEVER appear — the twin of `boot-test.sh`'s `FORBIDDEN_MARKERS`.
///
/// `LINUX GUEST TRAP` is the sharp one: `handle_linux_sync` prints it for any lower-EL synchronous
/// exception that is not an `HVC` — i.e. for every Stage-2 abort. A mis-emitted descriptor, a missing
/// device-window mapping, or a permission bit the kernel needs and does not get all land here. It is
/// what makes this job an assertion about the EMITTER and not merely about Linux.
const LINUX_FORBIDDEN: &[&str] = &[
    "baleen: LINUX GUEST TRAP",
    "Kernel panic",
    "baleen: linux model setup",
];

/// How long to let the boot run before declaring it hung. Generous on purpose: this is cross-arch
/// TCG on a CI runner, and the cost of a too-tight cap is an intermittently-red REQUIRED gate.
/// Overridable with `$BALEEN_LINUX_WAIT` (seconds) — the same escape hatch `boot-test.sh` gives.
const LINUX_WAIT_SECS_DEFAULT: u64 = 300;

/// Boot the real-Linux config headlessly and assert its markers. Returns whether every required
/// marker appeared and no forbidden one did; dumps the whole serial log on failure, since a boot
/// failure is diagnosed from the log or not at all.
fn boot_and_check_linux(argv: &[&str]) -> bool {
    use std::io::Read;
    use std::time::{Duration, Instant};

    let wait = std::env::var("BALEEN_LINUX_WAIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(LINUX_WAIT_SECS_DEFAULT);

    // The guest powers itself off (PSCI SYSTEM_OFF -> semihosting SYS_EXIT), so QEMU exits on its
    // own on a good boot. The deadline is for the bad ones: a kernel that panics into a spin, or an
    // EL2 park, would otherwise hang the job until the runner's own timeout with no log.
    // `std::env::temp_dir` plus the pid is enough uniqueness here: xtask is a task runner, and only
    // one of these runs at a time.
    let out = std::env::temp_dir().join(format!("baleen-qemu-linux-{}.log", std::process::id()));
    let log = match std::fs::File::create(&out) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("xtask qemu-linux-test: cannot open {}: {e}", out.display());
            return false;
        }
    };
    let errlog = match log.try_clone() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("xtask qemu-linux-test: cannot duplicate the log handle: {e}");
            return false;
        }
    };

    eprintln!("$ qemu-system-aarch64 {}", argv.join(" "));
    let mut child = match Command::new("qemu-system-aarch64")
        .args(argv)
        .stdout(log)
        .stderr(errlog)
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("xtask qemu-linux-test: cannot spawn qemu-system-aarch64: {e}");
            return false;
        }
    };

    let deadline = Instant::now() + Duration::from_secs(wait);
    let mut timed_out = true;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => {
                timed_out = false;
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => {
                eprintln!("xtask qemu-linux-test: wait failed: {e}");
                break;
            }
        }
    }
    if timed_out {
        let _ = child.kill();
        let _ = child.wait();
        eprintln!("xtask qemu-linux-test: the boot did not finish within {wait}s — killed");
    }

    let mut serial = String::new();
    if let Ok(mut f) = std::fs::File::open(&out) {
        // The kernel log is UTF-8 in practice, but a truncated multi-byte sequence at the kill point
        // must not turn a marker failure into a read failure.
        let mut bytes = Vec::new();
        let _ = f.read_to_end(&mut bytes);
        serial = String::from_utf8_lossy(&bytes).into_owned();
    }

    let mut failed = timed_out;
    for m in LINUX_MARKERS {
        if serial.contains(m) {
            println!("qemu-linux-test: OK — found '{m}'");
        } else {
            println!("qemu-linux-test: FAIL — marker '{m}' not found");
            failed = true;
        }
    }
    for m in LINUX_FORBIDDEN {
        if serial.contains(m) {
            println!("qemu-linux-test: FAIL — FORBIDDEN marker '{m}' appeared");
            failed = true;
        } else {
            println!("qemu-linux-test: OK — forbidden '{m}' absent");
        }
    }

    if failed {
        println!("----------------------------------------");
        print!("{serial}");
        println!("----------------------------------------");
        println!("qemu-linux-test: FAILED");
    } else {
        println!("qemu-linux-test: OK — a real Linux kernel booted behind the proven emitter and powered off");
    }
    let _ = std::fs::remove_file(&out);
    !failed
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
        // Every feature config that has code of its own, or that config's code is linted by nobody.
        // `smmu` and `real-linux` were both unlinted until the SMMU arc put a stream table, two
        // queues and a five-phase witness behind `smmu` — a feature gate is exactly where a
        // dead-code or clippy finding hides, since the default build cannot see it.
        && metal_clippy(&["--features", "smmu"])
        && metal_clippy(&["--features", "real-linux"])
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
