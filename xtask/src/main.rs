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
        // Both go through ONE `qemu_linux` (design-lesson #14c) — the gate must not be able to
        // pass against a QEMU invocation the demo does not use.
        "qemu-linux" => qemu_linux(false),
        "qemu-linux-test" => qemu_linux(true),
        "metal-lint" => metal_lint(),
        "doc-markers" => doc_markers(),
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
                && doc_markers()
        }
        other => {
            if !other.is_empty() {
                eprintln!("xtask: unknown task {other:?}\n");
            }
            // The config COUNT is interpolated from `METAL_LINT_CONFIGS`, not typed: this line
            // said "all four" while `metal_lint` ran five, because ⑭b added `real-linux,selftest`
            // and the prose stayed. A number a human retypes is a claim that drifts; a number the
            // compiler derives from the list it describes cannot.
            eprintln!(
                "usage: cargo xtask <task>\n  \
                 test   run the workspace test suite\n  \
                 check  type-check the workspace\n  \
                 doc    build docs, denying broken links\n  \
                 ci     fmt --check, clippy -D warnings, test, doc, then doc-markers\n  \
                 doc-markers  assert every boot marker a doc QUOTES is still one the gates check\n  \
                 qemu   boot hv-metal under QEMU (AArch64/EL2, interactive)\n  \
                 qemu-test  headless QEMU boot smoke-test (the metal CI check)\n  \
                 qemu-linux      boot a REAL Linux kernel under hv-metal (interactive demo)\n  \
                 qemu-linux-test the same boot, headless, asserting its markers (a CI check)\n  \
                 metal-lint fmt --check + clippy -D warnings for hv-metal ({} feature configs)",
                METAL_LINT_CONFIGS.len()
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
// The guest-RAM load layout — MUST match `hv-metal/src/stage2.rs`'s `LINUX_RAM_BASE`/`LINUX_RAM_END`
// (what the emitter maps), `hv-metal/src/linux.rs`'s `DTB_ADDR`, and `hv-metal/linux/guest.dts`.
// QEMU `-device loader` deposits each guest's three blobs at these PAs before hv-metal boots —
// SIX entries since ③-b2b-ii-b, because guest B's are guest A's plus `GUEST_B_OFFSET`.
//
// These three cannot be DERIVED from hv-metal: it is a workspace-excluded crate that does not link
// for the host, so xtask cannot depend on it. ⑭ made the contract one declaration everywhere it
// could reach and bound this last seam at RUN time instead — `LINUX_MARKERS` asserts hv-metal's
// banner *with its addresses in it*, and the boot only reaches userspace if the initrd address
// agrees too. That is a real check, not a comment: see the two entries in `LINUX_MARKERS`.
const LINUX_KERNEL_ADDR: u64 = LINUX_RAM_BASE; // Image (also guest A's DTB /memory base)
const LINUX_DTB_ADDR: u64 = 0x4b00_0000; // DTB (hv-metal points guest x0 here)
const LINUX_INITRD_ADDR: u64 = 0x4c00_0000; // initramfs (DTB /chosen linux,initrd-*)

/// The guest-RAM window and the ③-b2a split, mirroring `hv-metal/src/stage2.rs`'s `LINUX_RAM_BASE`
/// / `LINUX_RAM_SPLIT` / `LINUX_RAM_END`. Bound at RUN time by the banner marker, which prints all
/// three — the same seam as the load addresses above, for the same reason.
const LINUX_RAM_BASE: u64 = 0x4800_0000;
const LINUX_RAM_SPLIT: u64 = 0x6400_0000;
const LINUX_RAM_END: u64 = 0x8000_0000;

/// **Guest B's blobs sit exactly this far above guest A's** (③-b2b-ii-b) — a derivation, not a
/// fourth address to keep in step. It is also the size of each guest's half, which is why one
/// constant serves both roles below.
const GUEST_B_OFFSET: u64 = LINUX_RAM_SPLIT - LINUX_RAM_BASE;

/// The number of real-Linux guests xtask loads blobs for. Mirrors `hv-metal`'s `NUM_GUESTS`; a
/// disagreement shows up as a missing `linux model built for dom N` marker.
const NUM_GUESTS: u64 = 2;

// ─── the RAM QEMU actually creates (③-b2b-ii-b: the headroom guard) ──────────────────────────────

/// Where the `virt` machine puts DRAM, and how much the `-m` flag below asks for. **These two are
/// what QEMU really creates**, and until ③-b2b-ii-b nothing compared them against the window the
/// emitter hands out: `LINUX_RAM_END` is *exactly* the top of a 1024 MiB `-m`, so the fit is correct
/// and has zero headroom. Grow the window and QEMU simply never creates the memory, which presents
/// as a guest faulting on RAM its own DTB promised it.
const QEMU_RAM_BASE: u64 = 0x4000_0000;
const QEMU_RAM_MIB: u64 = 1024;
const QEMU_RAM_END: u64 = QEMU_RAM_BASE + QEMU_RAM_MIB * 1024 * 1024;

/// The emitter's whole guest-RAM window must exist in the machine `-m` builds. True or the build
/// fails — the half of the guard that needs no boot at all.
const _: () = assert!(
    LINUX_RAM_END <= QEMU_RAM_END,
    "the guest-RAM window runs past the DRAM `-m` creates: hv-metal would map memory QEMU never made"
);

/// The window must split into [`NUM_GUESTS`] equal halves at [`LINUX_RAM_SPLIT`], or "B's blobs are
/// A's plus the offset" stops being true and the loader addresses below drift out of their guest.
const _: () = assert!(
    LINUX_RAM_BASE + NUM_GUESTS * GUEST_B_OFFSET == LINUX_RAM_END,
    "the guest-RAM window must divide exactly into NUM_GUESTS halves at LINUX_RAM_SPLIT"
);

/// `(Image, DTB, initramfs)` load addresses for guest `slot`, and the base+size of its RAM window.
///
/// **One derivation for both guests.** Guest A's three addresses are the constants above; every
/// other guest's are those plus `slot * GUEST_B_OFFSET`, which is why the second kernel needed no
/// new address to be agreed with anybody — see `hv-metal/src/linux.rs`, which derives the same
/// three the same way and prints them for the marker below to assert.
fn guest_load_addrs(slot: u64) -> GuestLoad {
    let delta = slot * GUEST_B_OFFSET;
    GuestLoad {
        kernel: LINUX_KERNEL_ADDR + delta,
        dtb: LINUX_DTB_ADDR + delta,
        initrd: LINUX_INITRD_ADDR + delta,
        ram_base: LINUX_RAM_BASE + delta,
        ram_size: GUEST_B_OFFSET,
    }
}

/// The window belonging to guest `slot`'s peer — the address its peer-probe node names (③-b2b-ii-d).
fn peer_of(slot: u64) -> GuestLoad {
    guest_load_addrs((slot + 1) % NUM_GUESTS)
}

/// Where one guest's blobs go and what RAM window its DTB advertises.
struct GuestLoad {
    kernel: u64,
    dtb: u64,
    initrd: u64,
    ram_base: u64,
    ram_size: u64,
}

/// Boot a real aarch64 Linux kernel under hv-metal (M5 Arc 5e). Builds hv-metal `--features
/// real-linux`, renders and compiles ONE DTB PER GUEST from `guest.dts` (③-b2b-ii-b), and launches
/// QEMU with each guest's `Image` + DTB + initramfs loaded into its own half of guest RAM via
/// `-device loader`. The same `Image` and the same initramfs serve both guests — the kernel is
/// relocatable and the two device trees are what differ.
///
/// With `check` false this is the interactive demo: QEMU inherits stdio and you watch a kernel boot.
/// With `check` true it is the gate `.github/workflows/ci.yml`'s `real-linux boot (QEMU)` job runs —
/// the SAME QEMU line, with the output captured and [`LINUX_MARKERS`] / [`LINUX_FORBIDDEN`] asserted
/// against it. One derivation, so the gate cannot pass against a boot the demo does not perform.
///
/// The `Image` and `initramfs` come from `$BALEEN_LINUX_DIR` (default `.baleen-linux`, relative to
/// the repo root like every other path in this file, and the same location CI uses);
/// `hv-metal/linux/fetch-guest-image.sh` builds both from checksum-pinned official Alpine downloads.
fn qemu_linux(check: bool) -> bool {
    use std::path::PathBuf;

    let task = if check {
        "qemu-linux-test"
    } else {
        "qemu-linux"
    };
    // Relative, matching `hv-metal/linux/guest.dts` below and every other path here: xtask is run
    // from the repo root. Previously an absolute `~/forge/baleen-metal-linux/alpine`, which put local
    // runs in a different directory from CI's `$GITHUB_WORKSPACE/.baleen-linux` — see the note in
    // fetch-guest-image.sh for why that default existed and why it stopped making sense.
    let dir = std::env::var("BALEEN_LINUX_DIR").unwrap_or_else(|_| ".baleen-linux".to_string());
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

    // ③-b2b-ii-b: compile ONE DTB PER GUEST, both from `guest.dts` through the same routine.
    //
    // **Why not a second hand-written `.dts`.** The two descriptions differ in exactly three values
    // — the `/memory` node's name, its `reg`, and `/chosen`'s initrd range — and every other node,
    // including the PL011 and the GIC, is IDENTICAL because each guest gets its own EL2-backed model
    // at the same IPA. A second file would be a second declaration of the twenty lines that must not
    // differ, which is the defect ⑭ spent a rung removing (#74/#92b).
    //
    // **And why both go through the same call.** Guest A's substitution is an identity — it replaces
    // its own literals with themselves — so it looks like wasted work. It is not: a path only B
    // takes is a path only B's failures exercise, and the whole point of deriving B from A is that
    // they cannot drift. Running A through it too means the needle checks below guard A's DTB as
    // well, on every single boot.
    let initrd_size = std::fs::metadata(&initrd).map(|m| m.len()).unwrap_or(0);
    let mut dtbs = Vec::new();
    for slot in 0..NUM_GUESTS {
        match render_guest_dtb(task, &dir, slot, initrd_size) {
            Some(path) => dtbs.push(path),
            None => return false,
        }
    }

    if !metal_build_linux() {
        return false;
    }

    // `-device loader,file=…,addr=…,force-raw=on` deposits each blob at its guest PA before the
    // `-kernel` (hv-metal) boots at EL2; hv-metal then erets into the kernel with x0 = the DTB.
    let mut args: Vec<String> = vec![
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
        QEMU_RAM_MIB.to_string(),
        "-nographic".into(),
        "-net".into(),
        "none".into(),
        // Semihosting: hv-metal's SYSTEM_OFF handler issues a semihosting SYS_EXIT so QEMU exits
        // cleanly when the guest powers off (instead of parking until a timeout).
        "-semihosting".into(),
        "-kernel".into(),
        METAL_BIN.into(),
    ];

    // ③-b2b-ii-b: every guest's three blobs, and the guard that they land in RAM that EXISTS.
    //
    // `-device loader` writes wherever it is told. An address past the top of the DRAM `-m` created
    // is not refused by QEMU and not reported by it — the bytes simply are not there when hv-metal
    // erets, and the guest dies reading its own kernel. The window fits exactly today (see the
    // `const assert!` on `LINUX_RAM_END`), which is precisely the condition under which nobody
    // notices the check is missing.
    let mut blobs: Vec<(String, &std::path::Path, u64)> = Vec::new();
    for (slot, dtb) in dtbs.iter().enumerate() {
        let at = guest_load_addrs(slot as u64);
        blobs.push((
            format!("dom {} Image", slot + 1),
            image.as_path(),
            at.kernel,
        ));
        blobs.push((format!("dom {} DTB", slot + 1), dtb.as_path(), at.dtb));
        blobs.push((
            format!("dom {} initramfs", slot + 1),
            initrd.as_path(),
            at.initrd,
        ));
    }
    for (what, file, addr) in &blobs {
        let len = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
        if *addr < QEMU_RAM_BASE || addr.saturating_add(len) > QEMU_RAM_END {
            eprintln!(
                "xtask {task}: {what} would load at 0x{addr:x}..0x{:x}, outside the DRAM `-m \
                 {QEMU_RAM_MIB}` creates (0x{QEMU_RAM_BASE:x}..0x{QEMU_RAM_END:x}). QEMU would \
                 accept the -device loader silently and the guest would find nothing there.",
                addr + len
            );
            return false;
        }
        args.push("-device".into());
        args.push(format!(
            "loader,file={},addr=0x{addr:x},force-raw=on",
            file.display()
        ));
    }

    let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    if !check {
        return run("qemu-system-aarch64", &argv);
    }
    boot_and_check_linux(&argv)
}

/// Render and compile guest `slot`'s device tree from `hv-metal/linux/guest.dts`, returning the
/// `.dtb` path (③-b2b-ii-b).
///
/// **Every substitution is CHECKED, and that is the whole design.** `String::replace` that matches
/// nothing returns the string unchanged, so a constant here drifting from `guest.dts` would silently
/// ship a device tree describing the wrong machine — ⑭b already hit exactly that with `initrd-end`,
/// where the failure surfaced a layer away as "the kernel reached no userspace". Each needle below
/// is therefore required to be present, and its absence names the two things that disagree.
///
/// The four values are the only ones that differ between guests. Everything else — the PL011, the
/// GIC, the timer, `psci` — is identical, because each guest gets its own EL2-backed model at the
/// same IPA rather than a share of one device.
fn render_guest_dtb(
    task: &str,
    dir: &std::path::Path,
    slot: u64,
    initrd_size: u64,
) -> Option<std::path::PathBuf> {
    let src = "hv-metal/linux/guest.dts";
    let dts = match std::fs::read_to_string(src) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("xtask {task}: cannot read {src}: {e}");
            return None;
        }
    };

    let at = guest_load_addrs(slot);
    let dom = slot + 1;
    // The needles are guest A's literals — the file IS guest A's description, and rendering A is an
    // identity substitution that still has to find every one of them.
    let a = guest_load_addrs(0);
    let subs = [
        (
            format!("memory@{:x} {{", a.ram_base),
            format!("memory@{:x} {{", at.ram_base),
        ),
        (
            format!("reg = <0x00 0x{:x} 0x00 0x{:x}>;", a.ram_base, a.ram_size),
            format!("reg = <0x00 0x{:x} 0x00 0x{:x}>;", at.ram_base, at.ram_size),
        ),
        (
            format!("linux,initrd-start = <0x{:x}>;", a.initrd),
            format!("linux,initrd-start = <0x{:x}>;", at.initrd),
        ),
        (
            format!("linux,initrd-end = <0x{:x}>;", a.initrd),
            format!("linux,initrd-end = <0x{:x}>;", at.initrd + initrd_size),
        ),
        // ③-b2b-ii-d: the peer-probe node points at the OTHER guest's base — derived from the same
        // rotation `hv-metal`'s `next_runnable` uses, so "who is my peer" has one answer.
        (
            format!("peer-probe@{:x} {{", peer_of(0).ram_base),
            format!("peer-probe@{:x} {{", peer_of(slot).ram_base),
        ),
        (
            format!("reg = <0x00 0x{:x} 0x00 0x1000>;", peer_of(0).ram_base),
            format!("reg = <0x00 0x{:x} 0x00 0x1000>;", peer_of(slot).ram_base),
        ),
    ];

    // Checked by PRESENCE, not by "did the string change" — because guest A's substitutions are
    // identities, and a did-it-change test would silently skip every check on exactly the guest that
    // boots today. Presence is the same test for both.
    let mut rendered = dts;
    for (needle, replacement) in &subs {
        if !rendered.contains(needle.as_str()) {
            eprintln!(
                "xtask {task}: {src} has no `{needle}` to substitute — it and xtask's guest-RAM \
                 constants have drifted apart, and dom {dom}'s device tree would describe a machine \
                 this build does not create."
            );
            return None;
        }
        rendered = rendered.replace(needle, replacement);
    }

    let dts_out = dir.join(format!("guest-dom{dom}.dts"));
    let dtb_out = dir.join(format!("guest-dom{dom}.dtb"));
    if let Err(e) = std::fs::write(&dts_out, rendered) {
        eprintln!("xtask {task}: cannot write {}: {e}", dts_out.display());
        return None;
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
        eprintln!("xtask {task}: dtc failed to compile dom {dom}'s guest DTB");
        return None;
    }
    Some(dtb_out)
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
///   proven emitter actually wrote for THIS guest (448 blocks + the 16 MiB device window) and asserts
///   every other slot is dead. The one real guest's emission is the one that would otherwise never be
///   checked at runtime (M5 Arc 6b).
/// * **`Machine model: baleen-metal-guest`** — a string that exists only in `hv-metal/linux/
///   guest.dts`, echoed by the kernel. The kernel can only print it by READING the DTB at
///   `0x4b00_0000` through the emitted Stage-2 map AND driving the PL011 — which since ③-a1 is
///   **emulated in EL2**, not in the pass-through window, so the bytes additionally have to survive
///   `vpl011`'s relay to the real UART. Un-forgeable in the same way `ro=0x5eed` is on the synthetic
///   path.
/// * **`node   0: [mem 0x0000000048000000-0x0000000063ffffff]`** — THE MEMORY CONTRACT, in one
///   string. It is the kernel reporting the window it got from our DTB, and it must equal what the
///   emitter maps for **this domain** and the `-device loader` addresses above (where the blobs
///   land). Four places that must agree; this is the assertion that goes red when they stop.
///
///   **It ends at `0x63ffffff`, not `0x7fffffff`, since ③-b2a split the window** — the running
///   kernel is dom 1 and owns `LINUX_RAM_BASE..LINUX_RAM_SPLIT`, dom 2 the upper half. Note that
///   `xtask doc-markers` does NOT scan `.rs` files, only `docs/*.md`, so a stale marker quote in
///   THIS doc comment is caught by a human reading the diff or not at all — which is how the
///   `0x7fffffff` above survived one rung too long.
/// * **`Linux version 6.18.`** — an unmodified upstream Alpine kernel, not a stub that prints
///   markers.
/// * **`linux PSCI FID 0x84000006 -> NOT_SUPPORTED`** — the kernel's `MIGRATE_INFO_TYPE` probe
///   trapped from EL1 to EL2 and hv-metal's handler serviced it. The HVC path is live and the kernel
///   continued past it.
/// * **`Run /init as init process` + `BALEEN-STEP0-OK` + `baleen-guest-ram: …`** — the kernel
///   unpacked OUR initramfs from `0x4c00_0000` and reached userspace, which then reports the RAM
///   window from INSIDE the guest (`/proc/iomem`) — the guest-side half of the memory contract.
/// * **`vpl011 OK: the guest's console is EMULATED …`** — ③-a1's own witness, and the only one here
///   that can tell an EMULATED PL011 from a passed-through one. Every marker above it is a statement
///   about the kernel, and the kernel prints the same bytes either way: **measured — with the
///   pre-③ 32 MiB pass-through window restored, ten of the twelve markers that existed at ③-a1
///   stayed green.** This
///   one is printed by `hv-metal`'s own device model, and only if the userspace marker's bytes
///   arrived at its `DR` register — so widening the window back over `0x0900_0000` fails it. It is
///   deliberately an INGRESS claim; the egress half is **every kernel/userspace marker above**,
///   which the kernel cannot print unless the emulator relays its bytes to the real UART. (Stated
///   as "the markers above" rather than a count: the count has changed twice since it was written,
///   and a number nothing checks is a claim waiting to go stale.)
/// * **`vtimer OK: the guest's scheduler tick is FORWARDED …`** and **`vsgi OK: … SGIs MEDIATED …`**
///   — ③-a2's witnesses, and they exist for exactly the reason ③-a1's does: **every marker above
///   this point is satisfied identically with `HCR_EL2.IMO=0`**, because a kernel taking its timer
///   PPI directly prints the same bytes as one taking an injected virtual interrupt. These two are
///   counters incremented only inside EL2 trap handlers that `IMO=1` is what makes reachable, so
///   `IMO=0` sets both to zero and prints the `FAIL` twin instead (which `LINUX_FORBIDDEN` also
///   catches). They are INGRESS claims; the egress half is every marker above, which a guest with no
///   scheduler tick never reaches — a Linux guest that is not ticking does not get to `Run /init`.
/// * **`vgic OK: the guest's interrupt controller is EMULATED …`** — ③-b1, and the completion of the
///   set: the guest now drives **no real device MMIO at all**. Its counters come from
///   `hv-metal`'s own distributor model, which a pass-through configuration could not increment
///   because the writes would never reach EL2. Paired with the emitter's own `device window 0 MiB`
///   above, which says the same thing from the Stage-2 side.
/// * **`linux guest issued PSCI SYSTEM_OFF …`** — the whole round trip, and the reason the boot
///   terminates rather than parking: busybox `poweroff -f` -> the kernel's PSCI -> `HVC` -> EL2.
const LINUX_MARKERS: &[&str] = &[
    // hv-metal, before the guest runs. The ADDRESSES in this line are load-bearing, not decoration:
    // they are hv-metal's view of the memory contract, and xtask's `guest_load_addrs` is its own.
    // `hv-metal` is workspace-EXCLUDED (it cannot link for the host), so no compile-time derivation
    // can bind the two — ⑭ folded the contract into one declaration everywhere it *could* reach, and
    // this marker is what binds the remaining cross-crate seam. Change `LINUX_KERNEL_ADDR` or
    // `LINUX_DTB_ADDR` without changing hv-metal and this goes red here rather than hanging a guest.
    "baleen: M5 Arc 5e — booting 2 REAL aarch64 Linux kernels as EL1 guests time-slicing ONE pCPU \
     (dom 1 owns 0x48000000..0x64000000, dom 2 owns 0x64000000..0x80000000)",
    // ③-b2a: 224 leaves each, not 448 — the window is split. BOTH domains are asserted, so a
    // build that quietly stopped emitting the peer would redden here and not only at `peer OK`.
    "baleen: linux model built for dom 1 — 224 super-span leaves (448 MiB at 0x48000000) across 28 L2-pinned tables, into stage-2 set 0",
    "baleen: linux model built for dom 2 — 224 super-span leaves (448 MiB at 0x64000000) across 28 L2-pinned tables, into stage-2 set 1",
    // Two claims in one pair of strings. `device window 0 MiB` is ③-b1's, in the emitter's own
    // voice: the guest gets NO device pass-through at all (32 MiB at Arc 5e, 16 MiB once ③-a1
    // dropped the PL011 out, zero once ③-b1 emulated the GIC). The `set 0`/`set 1` split is
    // ③-b2a's: `verify_encoding` runs per set, so both images are read back independently.
    "(set 0: tables decode to exactly the authorized leaf map; image block absent (tables asserted dead); 224 super-span 2 MiB block(s) emitted and decoded; device window 0 MiB)",
    "(set 1: tables decode to exactly the authorized leaf map; image block absent (tables asserted dead); 224 super-span 2 MiB block(s) emitted and decoded; device window 0 MiB)",
    // The kernel, behind the proven emitter.
    "Linux version 6.18.",
    "Machine model: baleen-metal-guest",
    "node   0: [mem 0x0000000048000000-0x0000000063ffffff]",
    "baleen: linux PSCI FID 0x84000006 -> NOT_SUPPORTED",
    "Run /init as init process",
    // Userspace, out of our initramfs.
    "########## BALEEN-STEP0-OK ##########",
    "baleen-guest-ram: 48000000-63ffffff:SystemRAM",
    // ③-a1: the console every marker above travelled over is EMULATED.
    "baleen: vpl011 OK: dom 1's console is EMULATED — its own userspace's 'BALEEN-STEP0-OK' was \
     written to dom 1's emulated PL011 DR register in EL2",
    "baleen: vpl011 OK: dom 2's console is EMULATED — its own userspace's 'BALEEN-STEP0-OK' was \
     written to dom 2's emulated PL011 DR register in EL2",
    // ③-a2: the interrupts that DROVE the boot above are EL2's now. Same discipline as the vpl011
    // marker and for the same reason — a guest whose scheduler tick arrives by list-register
    // injection prints exactly what one taking the PPI directly prints, so every marker above this
    // point survives `IMO=0` unchanged. These two are printed by hv-metal's own counters, which
    // only the forwarding path increments.
    "baleen: vtimer OK: dom 1's scheduler tick is FORWARDED —",
    "baleen: vtimer OK: dom 2's scheduler tick is FORWARDED —",
    "of dom 1's SGIs MEDIATED at EL2 —",
    "of dom 2's SGIs MEDIATED at EL2 —",
    // ③-b1: the interrupt CONTROLLER the guest programmed was EL2 state too — the last real device
    // it was still driving. Counted by the emulator, so a pass-through configuration cannot produce
    // it: the writes would never have been seen.
    "baleen: vgic OK: dom 1's interrupt controller is EMULATED —",
    "baleen: vgic OK: dom 2's interrupt controller is EMULATED —",
    // ③-b2b-i: the guest was switched OUT and BACK through hv-core's scheduler, with every context
    // register poisoned in between. Unlike every marker above it, the evidence is not that a counter
    // moved — it is that the kernel SURVIVED: a register missing from the saved set stays poisoned
    // and the boot dies, so every marker after this line is a guest resumed from a context the metal
    // rebuilt from scratch. Probe-verified per register (six of ten tested are load-bearing).
    "baleen: vcpu OK: dom 1 was dispatched onto the pCPU",
    "baleen: vcpu OK: dom 2 was dispatched onto the pCPU",
    // ③-b2b-ii-b: EL2 read the bytes at BOTH guests' load addresses before either ran, and found a
    // real payload at each. Asserted with every value in place, because the values ARE the claim:
    // the `ARM\x64` magic, `d00dfeed` and the addresses can only be there if the six `-device
    // loader` entries above landed where this build and hv-metal independently computed they would.
    //
    // Nothing else in this gate can see dom 2's payload — dom 2 does not run, so a boot in which
    // QEMU wrote its `Image` to the wrong address is byte-for-byte the boot in which it did, and the
    // first symptom would arrive a rung later as guest B executing a window full of zeroes.
    //
    // BOTH lines are asserted, and that is what makes the pair self-instrumenting: dom 1's payload
    // is known-good because it boots on every run, so dom 1 green with dom 2 red says the check is
    // right and the load is wrong (design-lesson #118).
    //
    // `relocatable` is the load-bearing word. The second kernel needs no second build only because
    // this exact file may boot at a 2 MiB-aligned base anywhere in memory (`flags` bit 3); an Alpine
    // bump that lost that property would otherwise present as guest B hanging at instruction one.
    "baleen: guestimage OK: dom 1 — Image 'ARM\\x64' 34 MiB, relocatable, at 0x48000000; DTB 0xd00dfeed at 0x4b000000; gzip initramfs at 0x4c000000",
    "baleen: guestimage OK: dom 2 — Image 'ARM\\x64' 34 MiB, relocatable, at 0x64000000; DTB 0xd00dfeed at 0x67000000; gzip initramfs at 0x68000000",
    // ③-b2b-ii-a: the console is now MULTIPLEXED — EL2 buffers each guest's transmit stream to a
    // newline and emits whole lines tagged with the domain whose emulated PL011 received the bytes.
    //
    // **What this asserts TODAY is narrower than it looks, and saying so is the point.** With one
    // guest running, a hard-coded `[dom 1]` would pass this identically: the tag cannot be
    // falsified until there is a second guest to mis-tag. What it *does* witness is that the
    // multiplexer is in the byte path at all — delete `hv-metal/src/console.rs` and relay straight
    // to the hardware as before, and this goes red while `vpl011 OK` and every kernel marker stay
    // green, because the needle is matched inside the device model and the bytes still arrive.
    //
    // The tag becomes discriminating at ③-b2b-ii-c, where the `[dom 2]` twin of this line is the
    // arc's headline: both guests run the SAME initramfs, so `BALEEN-STEP0-OK` alone can never say
    // which kernel printed it, and the tag is EL2's own answer (which model instance took the byte)
    // rather than anything the guest could write.
    "[dom 1] ########## BALEEN-STEP0-OK ##########",
    // ★ ③-b2b-ii-c2's HEADLINE — the four lines only a SECOND running kernel can produce, each
    // carrying EL2's tag (which model instance received the byte) and guest B's own content in one
    // string. Both guests run the SAME initramfs and the same `Image`, so no guest-supplied content
    // alone can say which kernel printed it, and no EL2 tag alone says a kernel ran at all.
    //
    // `[dom 2] baleen-guest-ram: 64000000-7fffffff` is the strongest single assertion in this file:
    // it is dom 2's userspace reading dom 2's `/proc/iomem`, which requires dom 2's kernel to have
    // parsed dom 2's DTB and reached that RAM through dom 2's OWN Stage-2 image. Guest A cannot
    // produce that string — its window ends at 0x63ffffff, and the peer's half is unmapped in its
    // image (`peer OK`, walked from the descriptors before either guest ran).
    // Dom 2's KERNEL lines cannot be asserted tag-plus-content: `printk` puts its own timestamp
    // between the two (`[dom 2] [    0.000000] Linux version …`), and the timestamp varies. So the
    // kernel-side claim is made by CONTENT that only dom 2 can print — its `/memory` window — and
    // the tag-plus-content claims are the two userspace lines, which carry no timestamp.
    "  node   0: [mem 0x0000000064000000-0x000000007fffffff]",
    "[dom 2] ########## BALEEN-STEP0-OK ##########",
    "[dom 2] baleen-guest-ram: 64000000-7fffffff:SystemRAM",
    // ③-b2b-ii-a's own witness, and the only assertion here that can tell an INDEXED per-guest state
    // from a shared one. Everything else this rung changed is structural: with one guest running,
    // eight arrays-of-one behave exactly like the eight globals they replaced. What cannot survive a
    // shared field is dom 2 — never dispatched, so every one of its counters must read zero, against
    // a dom 1 that made hundreds of GIC traps and thousands of console bytes on the same boot.
    "baleen: perguest OK: the guests' device models, vCPU contexts and witnesses are INDEXED, not shared — all 11 of them are non-zero for EVERY one of the 2 guests",
    // ③-b2b-ii-c1: the ONE physical timer changes hands at every switch. Two counts, because the
    // handoff has two halves and one of them is invisible to the other:
    //
    //   * `demoted N … across N switches (exactly one each)` — the outgoing vCPU's `HW=1` list
    //     register becomes a purely virtual pending interrupt, since the physical line it claimed is
    //     about to belong to someone else. An equality, not a tally: exactly one hardware-mapped LR
    //     exists at a preemption point, so "some switches" and "all switches" are distinguishable.
    //   * `the redistributor confirmed PPI 27 went Active -> Inactive all N times` — read back from
    //     `GICR_ISACTIVER0`, i.e. the interrupt controller's own view rather than EL2's bookkeeping.
    //
    // The second exists because deleting the physical deactivate leaves the first perfectly green.
    // PROBED: with it deleted, guest A reaches userspace, prints `poweroff`, and HANGS — the tick
    // never comes again, and the tick is the only thing that re-enters EL2. That is the deadlock
    // this rung exists to prevent, reproduced on the guest that exists today.
    "baleen: handoff OK: dom 1 gave the forwarded timer up every time it left the pCPU holding one —",
    "baleen: handoff OK: dom 2 gave the forwarded timer up every time it left the pCPU holding one —",
    // ③-b2b-ii-c2 follow-up: an idle guest YIELDS. Without `HCR_EL2.TWI` a guest switched in while
    // idle sits in `wfi`, EL2 never gets a tick (the deadline it waits on is not one EL2 armed), and
    // the peer never runs again — both guests frozen. That reached `main` and timed out this very
    // job; it reproduced locally at 2 runs in 15. This marker is the evidence the trap is in force,
    // because a boot with the yield working and a boot that never switched to an idle guest look
    // otherwise identical.
    // ③-b2b-ii-c2 follow-up: an idle guest YIELDS instead of freezing the machine. Asserted as a
    // READ-BACK of `HCR_EL2`, not as a count of trapped WFIs — with two kernels sharing one pCPU
    // neither is ever short of work, so a boot in which nobody goes idle has a count of zero and is
    // perfectly good. (Measured: a run of this gate did exactly that, and an earlier version of the
    // witness refused it.) The read-back is true on every boot and is what actually determines
    // whether an idle guest can hold the CPU with no way for EL2 to take it back.
    "baleen: wfi OK: HCR_EL2.TWI is in force (HCR_EL2 read back as",
    // ★ ③-b2b-ii-d — THE LIVE NEGATIVE TEST, in both directions. Each guest's device tree names an
    // AMBA peripheral at the base of the OTHER guest's half of the window, so the kernel's bus scan
    // reads its identification registers during boot and the hardware refuses every one.
    //
    // The IPA is asserted with its value (`…000fe0`) because that value IS the claim: it is the
    // AMBA peripheral-ID register offset, so the access came from a real driver probe rather than
    // from anything hv-metal arranged. And the refusal is only interesting because EL2 checked, at
    // the moment of the fault, that the same address resolves to ITSELF in the peer's LIVE emitted
    // image and that the peer's loaded kernel is sitting there — an address that is merely unbacked
    // would fault for a boring reason.
    //
    // Both directions, because a one-way test would leave open that the asymmetry, not the map, is
    // what refused it. And the guest SURVIVES — every marker after this one is printed by a kernel
    // that took the abort and carried on, which is what separates a negative test from a crash.
    "baleen: peerfault OK: dom 1 touched dom 2's memory at IPA 0x64000fe0 and the HARDWARE refused it",
    "baleen: peerfault OK: dom 2 touched dom 1's memory at IPA 0x48000fe0 and the HARDWARE refused it",
    // ③-b2a: TWO domains, TWO Stage-2 images, disjoint — walked from the emitted descriptors
    // rather than recomputed from the layout constants the emitter used (design-lesson #36).
    // The claim is scoped ("over the guest-RAM window") because that is what the walk covers: 448
    // frames plus three out-of-window probes, not ∀-address. The ∀ statement is `hv-verify`'s.
    "baleen: peer OK: two domains, two Stage-2 images, DISJOINT over the guest-RAM window —",
    // The round trip home.
    "baleen: dom 1 issued PSCI SYSTEM_OFF — a real Linux kernel booted and shut down on hv-metal's EL2",
    "baleen: dom 2 issued PSCI SYSTEM_OFF — a real Linux kernel booted and shut down on hv-metal's EL2",
    "baleen: every real Linux guest has powered off — 2 unmodified kernels ran isolated on hv-metal's EL2 and shut down",
];

/// Strings that must NEVER appear — the twin of `boot-test.sh`'s `FORBIDDEN_MARKERS`.
///
/// `LINUX GUEST TRAP` is the sharp one: `handle_linux_sync` prints it for any lower-EL synchronous
/// exception that is not an `HVC` — i.e. for every Stage-2 abort. A mis-emitted descriptor, a missing
/// device-window mapping, or a permission bit the kernel needs and does not get all land here. It is
/// what makes this job an assertion about the EMITTER and not merely about Linux.
///
/// `baleen: vpl011 FAIL` is the negative half of ③-a1's witness: the device model prints it, with
/// its counters, whenever the boot ended without the guest's console having gone through it. A
/// missing marker and a printed failure are different failures, and both are worth naming.
const LINUX_FORBIDDEN: &[&str] = &[
    "baleen: LINUX GUEST TRAP",
    "Kernel panic",
    "baleen: linux model setup",
    "baleen: vpl011 FAIL",
    // ③-a2's negative halves. `vtimer FAIL` means EL2 never took a timer interrupt — with `IMO=1`
    // that is a guest running on a tick it should not have been able to receive. `vsgi FAIL` means
    // no `ICC_SGI1R_EL1` write ever trapped, i.e. the guest reached its own SGI generation register.
    "baleen: vtimer FAIL",
    "baleen: vsgi FAIL",
    // ③-b1's negative half: the guest's GIC accesses did not reach the emulator, i.e. the
    // distributor is being passed through again.
    "baleen: vgic FAIL",
    // ③-b2a: the two images overlap, one of them never got emitted, or an owned frame did not
    // resolve to its own identity mapping.
    "baleen: peer FAIL",
    // ③-b2b-i: the timer tick never reached the vCPU switch, so the context save/restore — and the
    // poison that makes it non-vacuous — was never exercised at all. A boot that is otherwise
    // perfect but never preempts proves nothing about the switch.
    "baleen: vcpu FAIL",
    // ③-b2b-ii-c1: the timer handoff did not fire on every switch — either the outgoing vCPU's
    // hardware-mapped list register was not demoted, or the redistributor did not agree the physical
    // PPI went Inactive. Both are the same consequence: the one physical timer stays Active across a
    // switch and the next guest can never be signalled it.
    "baleen: handoff FAIL",
    // ③-b2b-ii-c2 follow-up: no guest WFI reached EL2, so `HCR_EL2.TWI` is not in force and an idle
    // guest can hold the pCPU with no way for EL2 to take it back.
    // ③-b2b-ii-c2 follow-up: `HCR_EL2.TWI` did not take effect, so an idle guest holds the pCPU.
    "baleen: wfi FAIL",
    // ③-b2b-ii-d: a guest reached the peer's memory and the refusal proved nothing — the address is
    // mapped in its own image too, or it does not resolve in the peer's, or the peer's kernel is not
    // there. Any of those makes the negative test an anecdote.
    "baleen: peerfault FAIL",
    // ③-b2b-ii-b: a guest's window does not hold what the loader was told to put there — no kernel
    // magic, a zero image_size, a non-relocatable Image, a kernel overrunning its DTB, or a missing
    // device tree / initramfs. The message names which guest and which of the six checks failed.
    "baleen: guestimage FAIL",
    // ③-b2b-ii-a: a guest that has never been dispatched has a non-zero counter, i.e. the per-guest
    // device models / contexts / witnesses are still shared, or a handler is indexing them with the
    // wrong slot. The message names which counter leaked.
    "baleen: perguest FAIL",
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
        println!(
            "qemu-linux-test: OK — {NUM_GUESTS} real Linux kernels booted behind the proven \
             emitter, ran isolated on one pCPU, and powered off"
        );
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
/// Every `hv-metal` feature configuration `metal-lint` covers — the ONE place the set is written
/// down, so anything that wants to state its size (the usage text) derives the number instead of
/// repeating it.
///
/// Every feature config that has code of its own is here, or that config's code is linted by
/// nobody. `smmu` and `real-linux` were both unlinted until the SMMU arc put a stream table, two
/// queues and a five-phase witness behind `smmu` — a feature gate is exactly where a dead-code or
/// clippy finding hides, since the default build cannot see it.
///
/// ⑭b — THE INVARIANT THIS LIST HAS TO HOLD: **every configuration that is BUILT AND BOOTED is
/// linted.** It did not. The list carried `real-linux`, which nothing ships, while `qemu-linux`/
/// `qemu-linux-test` build `real-linux,selftest` — so the binary the REQUIRED `real-linux boot
/// (QEMU)` job boots was linted by nothing at all. Probed: a constant behind
/// `#[cfg(all(feature = "real-linux", feature = "selftest"))]` left `metal-lint` green while the
/// shipped build warned. That is ⑭'s own finding one level up — ⑭ asked "which config lints
/// `linux.rs`?" and fixed it, but not "does the linted set EQUAL the shipped set?".
///
/// Where the shipped set is defined, so a new config has an obvious home here:
///   default · selftest · smmu   -> `hv-metal/boot-test.sh`'s `boot_and_check` invocations
///   real-linux,selftest         -> `metal_build_linux` below
/// `real-linux` alone is kept too: it is seconds, and it covers the non-selftest path.
const METAL_LINT_CONFIGS: &[&[&str]] = &[
    &[],
    &["--features", "selftest"],
    &["--features", "smmu"],
    &["--features", "real-linux"],
    &["--features", "real-linux,selftest"],
];

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
    ) && METAL_LINT_CONFIGS.iter().all(|cfg| metal_clippy(cfg))
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

// ─── The doc-marker drift check ─────────────────────────────────────────────────────────────────
//
// WHY THIS EXISTS. A doc that QUOTES a boot marker is asserting that the build still emits that
// exact string — and that is a claim a machine can check, so it should not be left to a reader.
// It had already gone false: `docs/ARC6B-LINUX-ON-THE-PROVEN-EMITTER.md` quoted `… device window
// 32 MiB` as its `verify_encoding` evidence, and ③-a1 shrank the window to 16 MiB. That is the ⑭
// class exactly (a comment claiming something the code stopped doing), one scope out from code.
//
// THE RULE, which is TOTAL over the gate list and needs no annotation in the docs. For every gate
// marker, wherever a doc's backtick-quoted span contains that marker's first [`DOC_MARKER_STEM`]
// characters, the span must go on matching it until one of three things happens:
//   * the marker is exhausted        — the doc quotes it in full;
//   * the quoted span ends           — a legal truncation (`\`448 super-span 2 MiB block(s)\``);
//   * an explicit elision appears    — `…` or `...`, which makes the abridgement visible.
// Anything else is the doc asserting a string the gates no longer contain, and fails.
//
// WHY IT DOES NOT FALSE-ALARM. Nothing here guesses which prose "looks like a marker" — the check
// is driven entirely FROM the marker list, and a 24-character stem of a boot marker does not occur
// in prose by accident. The one real hazard is sibling markers that differ only in an index
// (`Mfn 4`/`Mfn 5`, `tenant 0`/`tenant 1`): a doc quoting one would diverge from the other. So
// candidates are grouped by the OFFSET their stem matched, and a divergence is drift only when
// EVERY candidate at that offset diverges. Measured on the tree that introduced this check: 114
// markers × 31 docs, 2 findings, 0 false positives.
//
// WHAT IT DOES NOT COVER, stated rather than implied: a doc that PARAGRAPHS a marker instead of
// quoting it is invisible here. `ARC6B`'s "32 MiB, GICv3 + PL011" table row was found by reading,
// not by this check, and a future one would be too. This closes the quoted half.

/// How much of a marker must appear verbatim in a doc before the doc counts as quoting it.
/// Long enough that prose cannot collide with it; short enough that most markers are covered.
const DOC_MARKER_STEM: usize = 24;

/// The other half of the gate corpus: `boot-test.sh`'s marker arguments. `LINUX_MARKERS` and
/// `LINUX_FORBIDDEN` need no parsing — they are consts in this binary — but the synthetic gate's
/// markers live in the shell script, so they are read from it.
const BOOT_TEST: &str = "hv-metal/boot-test.sh";

/// Assert that every boot marker a doc QUOTES is still a marker the gates check. See the block
/// comment above for the rule and its limits.
fn doc_markers() -> bool {
    eprintln!("$ xtask doc-markers");

    // The gate corpus.
    let mut gate: Vec<String> = LINUX_MARKERS
        .iter()
        .chain(LINUX_FORBIDDEN.iter())
        .map(|m| collapse(m))
        .collect();
    let script = match std::fs::read_to_string(BOOT_TEST) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("doc-markers: cannot read {BOOT_TEST}: {e}");
            return false;
        }
    };
    for line in script.lines() {
        if let Some(s) = shell_string(line) {
            gate.push(collapse(&s));
        }
    }
    gate.sort();
    gate.dedup();

    // The docs.
    let mut docs = vec![std::path::PathBuf::from("README.md")];
    match std::fs::read_dir("docs") {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == "md") {
                    docs.push(path);
                }
            }
        }
        Err(e) => {
            eprintln!("doc-markers: cannot read docs/: {e}");
            return false;
        }
    }
    docs.sort();

    let (mut quoted, mut findings) = (0usize, 0usize);
    for path in &docs {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("doc-markers: cannot read {}: {e}", path.display());
                return false;
            }
        };
        for (line, span) in quoted_spans(&text) {
            // Candidates grouped by the offset their stem matched (see the block comment).
            let mut by_offset: Vec<(usize, bool, &str, usize)> = Vec::new();
            for marker in &gate {
                let stem: String = marker.chars().take(DOC_MARKER_STEM).collect();
                let Some(at) = span.find(&stem) else { continue };
                let rest = &span[at..];
                let matched = rest
                    .chars()
                    .zip(marker.chars())
                    .take_while(|(a, b)| a == b)
                    .count();
                let tail: String = rest.chars().skip(matched).collect();
                let tail = tail.trim_start();
                let ok = matched == marker.chars().count()   // quoted in full
                    || matched == rest.chars().count()       // truncated at the span's end
                    || tail.starts_with('…')
                    || tail.starts_with("...");
                by_offset.push((at, ok, marker.as_str(), matched));
            }
            let offsets: Vec<usize> = {
                let mut v: Vec<usize> = by_offset.iter().map(|c| c.0).collect();
                v.sort_unstable();
                v.dedup();
                v
            };
            for at in offsets {
                let here: Vec<_> = by_offset.iter().filter(|c| c.0 == at).collect();
                if here.iter().any(|c| c.1) {
                    quoted += 1;
                    continue;
                }
                // Report the closest candidate — the marker this quote was plainly derived from.
                let worst = here.iter().max_by_key(|c| c.3).expect("non-empty");
                let doc_has: String = span[at..].chars().take(120).collect();
                eprintln!(
                    "doc-markers: FAIL {}:{line} — quotes a marker the gates no longer contain\n  \
                     gate has: {}\n  doc has : {}\n  (diverges after {} characters)",
                    path.display(),
                    worst.2,
                    doc_has,
                    worst.3
                );
                findings += 1;
            }
        }
    }

    if findings == 0 {
        eprintln!(
            "doc-markers: OK — {} gate markers, {} docs, {quoted} quoted marker(s) still exact",
            gate.len(),
            docs.len()
        );
        true
    } else {
        eprintln!(
            "doc-markers: {findings} doc(s) quote a boot marker the build no longer emits. \
             Update the doc to the marker's current text, or make the abridgement explicit with `…`."
        );
        false
    }
}

/// Collapse every run of whitespace to a single space, so a marker that wraps across source lines
/// (a `\`-continued Rust literal, a `>`-prefixed blockquote) compares equal to its printed form.
fn collapse(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The double-quoted string a `boot-test.sh` marker line consists of, if this line is one.
/// Markers are one per line and the line starts with the quote, which is what makes this reliable
/// without a shell parser.
fn shell_string(line: &str) -> Option<String> {
    let rest = line.trim().strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?),
            '"' => return Some(out),
            _ => out.push(c),
        }
    }
    None
}

/// Every backtick-quoted span in a markdown file, with the line its paragraph starts on.
///
/// Flattened per PARAGRAPH rather than per line: these docs wrap quoted markers across lines and
/// behind `>` blockquote prefixes, and a per-line scan silently misses them — which is how the
/// `device window 32 MiB` claim survived a first, per-line pass. A markdown code span cannot cross
/// a blank line, so paragraphs are the widest unit in which backticks still pair correctly.
/// Fenced code blocks are skipped: their backticks would offset the pairing of everything after.
fn quoted_spans(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut para: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut fenced = false;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with("```") {
            fenced = !fenced;
            flush_paragraph(&para, start, &mut out);
            para.clear();
        } else if fenced {
            continue;
        } else if line.is_empty() {
            flush_paragraph(&para, start, &mut out);
            para.clear();
        } else {
            if para.is_empty() {
                start = i + 1;
            }
            para.push(raw);
        }
    }
    flush_paragraph(&para, start, &mut out);
    out
}

/// Join one paragraph into a single line (dropping blockquote prefixes) and emit its backtick
/// spans — the odd-numbered pieces of a split on the backtick.
fn flush_paragraph(para: &[&str], start: usize, out: &mut Vec<(usize, String)>) {
    if para.is_empty() {
        return;
    }
    let joined = para
        .iter()
        .map(|l| l.trim_start().trim_start_matches('>').trim_start())
        .collect::<Vec<_>>()
        .join(" ");
    for (n, piece) in joined.split('`').enumerate() {
        if n % 2 == 1 {
            out.push((start, collapse(piece)));
        }
    }
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
