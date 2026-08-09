// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Baleen's task runner. Invoke as `cargo xtask <task>` (see `.cargo/config.toml`).
//!
//! Deliberately tiny for M1 — it grows to cover `hv-metal` cross-builds and the
//! `hv-fuzz` targets as those milestones land.

// ㉔ — **every private item carries a doc, and the reason is a defect the compiler could not see.**
//
// Inserting an item between a doc comment and the item it documents **silently re-parents the whole
// block**: the new item inherits the doc, and the old one is left with none. That is valid Rust,
// clippy's defaults are silent, and `git diff` renders it as clean ADDED lines with no signal that
// the lines *above* changed meaning — so it is invisible in the artifact you review and legal in the
// artifact you build. It happened twice in this file within one day (⑳-f re-parented
// `METAL_LINT_CONFIGS`'s doc onto a `&str` const; ㉓ re-parented `deep_sweeps`'s onto
// `proof_gate_test`), the second time four hours after the lesson about it was written, by its
// author.
//
// ★ **The point is not the docs, it is that the DISPLACED item is left bare** — which this lint
// sees. MEASURED, by re-creating ㉓'s defect: clippy goes from clean to
// `error: missing documentation for a function`, on the exact function that lost its doc.
//
// ⚠ **A PARTIAL guard, and worth knowing which part.** It catches "item left with no doc at all",
// which is both real instances. It does NOT catch a doc block split in the MIDDLE (the item keeps a
// partial doc and stays silent), nor a doc attached to the wrong item when both have one — ⑳-f's
// other defect, where the `metal_lint` task's description sat on `METAL_LINT_CONFIGS` for several
// arcs. Reading the diff is still the only thing that catches those.
//
// ⚠ It also flags a `///` that describes a GROUP while sitting on the group's first member — which
// is the same defect one size down, and is what five of this file's thirteen findings were.
//
// Why here and not everywhere: `hv-hal` (0 findings) and `hv-s2` (1) get it because enabling there
// LOCKS IN a property already held. `hv-core` has 59 and is deliberately left out — that is real
// documentation work, not filler, but it is larger than one rung.
#![warn(clippy::missing_docs_in_private_items)]

use std::io::{BufRead, BufReader};
use std::process::{exit, Command, Stdio};

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
        "qemu-linux" => qemu_linux(false, LinuxBoot::Shipped),
        // THREE boots, and the last two are witnesses the shipped guest cannot produce. The first
        // is the product: both guests power off. The other two each make dom 1's OWN driver core
        // commit a fault — one unmapped access, one loop that crosses `MAX_PEER_FAULTS` — and each
        // asserts that dom 2, which did nothing, runs to completion and powers off. Both used to
        // park the machine and take dom 2 down with it. ~5 s for the set.
        //
        // Sequential `let`s, not `a && b && c`: `&&` short-circuits, and the boots that would be
        // skipped are exactly the newer, less-trusted ones.
        "qemu-linux-test" => {
            // NOT `a && b`: that short-circuits, so a failing shipped boot would skip the fault
            // boot entirely and the log would say nothing about it. Both always run, and the run
            // that failed is always named.
            let shipped = qemu_linux(true, LinuxBoot::Shipped);
            let faulted = qemu_linux(true, LinuxBoot::UnmappedFault);
            let looped = qemu_linux(true, LinuxBoot::PeerLoop);
            let smmu = qemu_linux(true, LinuxBoot::Smmu);
            shipped && faulted && looped && smmu
        }
        // ⑲-1b — the same boot `qemu-linux-test` now runs as its fourth configuration, kept as a
        // named task for running it alone during SMMU work. It is NOT a local-only escape hatch:
        // see `LINUX_SMMU_MARKERS` for why that is no longer needed.
        "qemu-linux-smmu" => qemu_linux(true, LinuxBoot::Smmu),
        "metal-lint" => metal_lint(),
        "fvp-lint" => fvp_lint(),
        "doc-markers" => doc_markers(),
        "verus-counts" => verus_counts(),
        "kani-harnesses" => kani_harnesses(),
        "sweeps" => deep_sweeps(),
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
                // ⑳-c: ~2 s (`--list` enumerates without running), so unlike the proof-corpus
                // inventories this one is affordable on EVERY PR rather than only proof-path ones.
                && deep_sweeps()
                // ㉓: the gate that decides whether the PROOF gate runs. It lives here, in the
                // REQUIRED `fmt · clippy · test` context, and deliberately not in `proofs.yml` —
                // a test that runs only when proof paths change cannot catch the defect where the
                // decision to run wrongly says "nothing changed". Seconds; a temp repo and 7 cases.
                && proof_gate_test()
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
                 verus-counts assert every Verus file discharges the obligations it is expected to\n  \
                 kani-harnesses  run the Kani corpus and assert it contains exactly the expected harnesses\n  \
                 sweeps assert the deep exhaustive-sweep corpus is exactly the expected one\n  \
                 qemu   boot hv-metal under QEMU (AArch64/EL2, interactive)\n  \
                 qemu-test  headless QEMU boot smoke-test (the metal CI check)\n  \
                 qemu-linux      boot a REAL Linux kernel under hv-metal (interactive demo)\n  \
                 qemu-linux-test the same boot, headless, asserting its markers (a CI check)\n  \
                 qemu-linux-smmu just the SMMU boot configuration, run alone\n  \
                 metal-lint fmt --check + clippy + rustdoc, all -D warnings, for hv-metal ({} feature configs)\n  \
                 fvp-lint   the same bar for fvp-probe, the other workspace-excluded crate (build only — CI cannot run the AEM)",
                METAL_LINT_CONFIGS.len()
            );
            exit(2);
        }
    };
    if !ok {
        exit(1);
    }
}

/// The bare-metal target `hv-metal` builds for. `softfloat` because EL2 code must not use the FP
/// registers it is responsible for saving and restoring on a guest's behalf.
const METAL_TARGET: &str = "aarch64-unknown-none-softfloat";
/// Where the release build of `hv-metal` lands — the binary every boot task hands to QEMU.
/// ⚠ Spells [`METAL_TARGET`] out rather than interpolating it: `cargo`'s output path is `cargo`'s
/// to choose, so this is an observation about where it puts things, not a derivation from the flag.
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
/// Where guest A's kernel `Image` is deposited — and, being the base of its window, the `/memory`
/// base its DTB advertises.
const LINUX_KERNEL_ADDR: u64 = LINUX_RAM_BASE;
/// Where guest A's compiled DTB is deposited. `hv-metal` points the guest's `x0` here on `eret`.
const LINUX_DTB_ADDR: u64 = 0x4b00_0000;
/// Where guest A's initramfs is deposited. The DTB's `/chosen linux,initrd-{start,end}` must name
/// this, or the kernel boots and finds no userspace — which is why the marker list asserts a
/// userspace line rather than only a kernel one.
const LINUX_INITRD_ADDR: u64 = 0x4c00_0000;

// The guest-RAM window and the ③-b2a split, mirroring `hv-metal/src/stage2.rs`'s `LINUX_RAM_BASE`
// / `LINUX_RAM_SPLIT` / `LINUX_RAM_END`. Bound at RUN time by the banner marker, which prints all
// three — the same seam as the load addresses above, for the same reason.
//
// ⚠ ㉔ — this was ONE `///` describing THREE constants, attached to the first. That is the same
// defect the crate-level lint exists for, one size down: a doc on `LINUX_RAM_BASE` that is really
// about the window. The group rationale is a `//` block now, and each constant says what IT is.

/// The bottom of the guest-RAM window, and guest A's base.
const LINUX_RAM_BASE: u64 = 0x4800_0000;
/// The boundary between guest A's half and guest B's (③-b2a). Each guest owns exactly one side; the
/// isolation witness is that neither can reach across it.
const LINUX_RAM_SPLIT: u64 = 0x6400_0000;
/// The top of the guest-RAM window. **Exactly the top of a 1024 MiB `-m`** — see [`QEMU_RAM_END`]
/// and the `const` assertion below, which is what keeps that true.
const LINUX_RAM_END: u64 = 0x8000_0000;

/// **Guest B's blobs sit exactly this far above guest A's** (③-b2b-ii-b) — a derivation, not a
/// fourth address to keep in step. It is also the size of each guest's half, which is why one
/// constant serves both roles below.
const GUEST_B_OFFSET: u64 = LINUX_RAM_SPLIT - LINUX_RAM_BASE;

/// The number of real-Linux guests xtask loads blobs for. Mirrors `hv-metal`'s `NUM_GUESTS`; a
/// disagreement shows up as a missing `linux model built for dom N` marker.
const NUM_GUESTS: u64 = 2;

// ─── the RAM QEMU actually creates (③-b2b-ii-b: the headroom guard) ──────────────────────────────

// Where the `virt` machine puts DRAM, and how much the `-m` flag below asks for. **These are what
// QEMU really creates**, and until ③-b2b-ii-b nothing compared them against the window the emitter
// hands out: `LINUX_RAM_END` is *exactly* the top of a 1024 MiB `-m`, so the fit is correct and has
// ZERO headroom. Grow the window and QEMU simply never creates the memory, which presents as a guest
// faulting on RAM its own DTB promised it.

/// Where the `virt` machine places DRAM. A machine fact, not a choice of ours.
const QEMU_RAM_BASE: u64 = 0x4000_0000;
/// What the `-m` flag asks QEMU for, in MiB. **Changing this without changing [`LINUX_RAM_END`] is
/// what the `const` assertion below catches** — in the direction that matters, since shrinking the
/// machine silently un-creates memory the emitter still hands out.
const QEMU_RAM_MIB: u64 = 1024;
/// The top of the DRAM QEMU actually creates — derived, so it cannot drift from the `-m` above.
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

/// ⑲-3a — how much of the top of each guest's window is reserved `no-map` as the DMA landing pad.
///
/// 2 MiB, and the size is not arbitrary: a Stage-2 block on this platform is 2 MiB, so a pad of
/// exactly one block cannot force the emitter to split a mapping it would otherwise make whole, and
/// the reservation cannot straddle two of them. It sits at the TOP of the window rather than
/// anywhere else because that is the one place whose address is a function of the split alone.
const LINUX_DMA_PAD_SIZE: u64 = 0x20_0000;

/// The base of guest `slot`'s DMA landing pad — the top [`LINUX_DMA_PAD_SIZE`] of its own window.
///
/// Mirrors `hv-metal/src/linux.rs`'s `dma_pad_ipa`. The two derivations are checked against each
/// other by [`render_guest_dtb`]'s substitution check plus the `dmapad` witness, which walks this
/// address in the guest's live Stage-2 image and refuses to assert anything if it maps nothing.
fn dma_pad_base(slot: u64) -> u64 {
    let at = guest_load_addrs(slot);
    at.ram_base + at.ram_size - LINUX_DMA_PAD_SIZE
}

/// Where the fault-probe node sits — an IPA in **no** window this build maps or emulates.
///
/// Chosen and CHECKED against the four things that could make it inert: the emulated GIC
/// (`0x0800_0000..0x0900_0000`), the emulated PL011 (`0x0900_0000` + `0x1000`), guest RAM (from
/// `0x4800_0000`), and the Stage-2 device pass-through window, which `hv-metal` pins to ZERO with a
/// `const assert!`. A node inside any of them would be serviced instead of faulting, and the probe
/// would pass while testing nothing.
const FAULT_PROBE_ADDR: u64 = 0x0C00_0000;

/// Which of the three real-Linux boots the gate is running.
///
/// The shipped one is the product; the other two exist because **the shipped guest is cooperative and
/// cannot demonstrate what happens when a guest is not.** Each retires dom 1 by a DIFFERENT route and
/// asserts that dom 2 — which did nothing — runs to completion and powers off.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LinuxBoot {
    /// The product: both guests power off cleanly.
    Shipped,
    /// Dom 1's device tree names a peripheral at an address in no window, so its own bus scan takes
    /// a Stage-2 abort EL2 has no rule for.
    UnmappedFault,
    /// Dom 1's device tree names **many** peripherals inside its PEER's RAM, so its bus scan crosses
    /// `MAX_PEER_FAULTS` and it is retired for LOOPING rather than for one bad access.
    PeerLoop,
    /// ★ ⑲-1 — **the same shipped boot, on a machine that HAS an SMMU and a real bus master.**
    ///
    /// Identical guests, identical device trees; the machine gains `iommu=smmuv3` and a live `edu`
    /// PCIe device, and hv-metal is built with `smmu` as well. Until this rung the two halves of the
    /// isolation claim had never been in one machine: every DMA result came from a boot with no real
    /// guest, and every real-guest boot had no bus master.
    ///
    /// It asserts BOTH corpora — the full shipped real-Linux marker set *and* the SMMU's rung-1/2
    /// markers — so neither half can rot behind the other.
    Smmu,
}

/// How many extra peer-probe nodes the [`LinuxBoot::PeerLoop`] device tree carries.
///
/// **Sized from measurement, not taste.** One peer-probe node yields exactly **48** peer faults per
/// boot (measured: `PFPROBE dom 1 peer_faults=48`, and the driver core's re-probing is why it is 48
/// rather than 8). `MAX_PEER_FAULTS` is 4096, so 86 nodes would just cross it; 128 crosses it with
/// ~50% margin so the witness does not sit on the threshold it is testing.
const PEER_LOOP_NODES: u64 = 128;

/// The window belonging to guest `slot`'s peer — the address its peer-probe node names (③-b2b-ii-d).
fn peer_of(slot: u64) -> GuestLoad {
    guest_load_addrs((slot + 1) % NUM_GUESTS)
}

/// Where one guest's blobs go and what RAM window its DTB advertises.
///
/// One value per guest, derived from the slot — so guest B's addresses are guest A's plus
/// [`GUEST_B_OFFSET`] rather than a second set of constants to keep in step.
struct GuestLoad {
    /// PA the kernel `Image` is loaded at.
    kernel: u64,
    /// PA the compiled DTB is loaded at; the guest's `x0` on entry.
    dtb: u64,
    /// PA the initramfs is loaded at; must match the DTB's `/chosen linux,initrd-*`.
    initrd: u64,
    /// Base of the RAM window this guest's DTB advertises as `/memory`.
    ram_base: u64,
    /// Size of that window. `ram_base + ram_size` must stay inside [`QEMU_RAM_END`].
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
fn qemu_linux(check: bool, boot: LinuxBoot) -> bool {
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
        match render_guest_dtb(task, &dir, slot, initrd_size, boot) {
            Some(path) => dtbs.push(path),
            None => return false,
        }
    }

    if !metal_build_linux(boot) {
        return false;
    }

    // `-device loader,file=…,addr=…,force-raw=on` deposits each blob at its guest PA before the
    // `-kernel` (hv-metal) boots at EL2; hv-metal then erets into the kernel with x0 = the DTB.
    let mut args: Vec<String> = vec![
        "-M".into(),
        // ⑲-1: the SMMU boot adds `iommu=smmuv3`. QEMU's SMMUv3 fronts the PCIe root complex, which
        // is why the bus master below is a PCIe device and not the virtio-mmio the guests use.
        match boot {
            LinuxBoot::Smmu => "virt,virtualization=on,gic-version=3,iommu=smmuv3".into(),
            _ => "virt,virtualization=on,gic-version=3".to_string(),
        },
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

    // ★ ⑲-1 — the bus master. `dma_mask` is not decoration: `edu` defaults to a 28-bit mask, which
    // cannot reach the metal's sentinel, so the device would silently transfer nothing and the SMMU
    // markers would fail for a reason that has nothing to do with the SMMU. `boot-test.sh` learned
    // that the hard way and says so; this is the same line, for the same reason.
    if boot == LinuxBoot::Smmu {
        // ★★ ⑲-1b — **`arm-smmuv3.stage=2` IS WHAT MAKES THIS BOOT RUNNABLE ON CI, and its absence
        //    is what made ⑲-1 conclude the opposite.** QEMU's SMMUv3 advertises stage-2 only when
        //    asked: the property is `"1"` — stage-1 only — BY DEFAULT, and has existed since QEMU
        //    8.1 (merged to target-arm.next 2023-05). The runner has 8.2.2, so the capability was
        //    there the whole time and nothing was requesting it.
        //
        // ⚠ **⑲-1 read `IDR0.S2P = 0` on CI and concluded "the runner's QEMU cannot do stage-2".**
        // That inferred a missing CAPABILITY from an unrequested one, on a single register read —
        // and it nearly bought a staleness tripwire for coverage we could simply have had. MEASURED
        // with the flag: all five SMMU markers found ON THE RUNNER, `DEFAULT-DENY` included.
        //
        // `stage=2` means stage-2 ONLY, which is exactly right here: baleen drives the SMMU from the
        // same `p2m`-derived Stage-2 tables the CPU walks and wants no stage-1 at all.
        args.push("-global".into());
        args.push("arm-smmuv3.stage=2".into());
        args.push("-device".into());
        args.push("edu,dma_mask=0xffffffffff".into());
        // ★ ㉑ — a SECOND bus master, and it is the whole rung. QEMU puts consecutive `-device edu`s
        // at PCIe slots 1 and 2, so their RequesterIDs — and therefore their StreamIDs — are 8 and
        // 16 (VERIFIED with `query-pci` before this line was written: both enumerate, vendor 0x1234
        // device 0x11e8). Two requesters is the only way to show the SMMU's *translation* is
        // per-stream rather than merely its *permission*: with one device, "bound to dom 1's tables"
        // and "configured for dom 1" are the same observation.
        args.push("-device".into());
        args.push("edu,dma_mask=0xffffffffff".into());
    }

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
    boot_and_check_linux(&argv, boot)
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
    boot: LinuxBoot,
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
        // ⑲-3a: the DMA landing pad — the top `LINUX_DMA_PAD_SIZE` of this guest's own window,
        // reserved `no-map`. Derived from `ram_base`/`ram_size` here and from the frame count in
        // `hv-metal`, so the checked substitution below is what keeps the two derivations honest.
        (
            format!("dma-pad@{:x} {{", dma_pad_base(0)),
            format!("dma-pad@{:x} {{", dma_pad_base(slot)),
        ),
        (
            format!(
                "reg = <0x00 0x{:x} 0x00 0x{:x}>;",
                dma_pad_base(0),
                LINUX_DMA_PAD_SIZE
            ),
            format!(
                "reg = <0x00 0x{:x} 0x00 0x{:x}>;",
                dma_pad_base(slot),
                LINUX_DMA_PAD_SIZE
            ),
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

    // ── the fault probe (dom 1 only, probe run only) ────────────────────────────────────────────
    //
    // **A node, not a simulated call, and the precedent is ③-b2b-ii-d.** That rung made the guest's
    // OWN driver core touch a peer address by describing an AMBA peripheral there; the kernel's bus
    // scan reads the identification registers during boot, and the read is the test. The same trick
    // makes a guest commit a fault EL2 has no rule for, so what is witnessed is a REAL guest-caused
    // fault rather than EL2 invoking its own retire path.
    //
    // `FAULT_PROBE_ADDR` is outside EVERY window this build maps or emulates — the emulated GIC
    // (0x0800_0000..0x0900_0000), the emulated PL011 (0x0900_0000 + 0x1000), both guests' RAM (from
    // 0x4800_0000), and a Stage-2 device pass-through window that is a `const assert!`-ed ZERO. So
    // the scan's read of base+0xFE0 lands in no window and takes the "outside every emulated device"
    // path, which before this rung parked the machine.
    //
    // **Inserted here rather than living in `guest.dts`**, because a second `.dts` would be a second
    // declaration of the twenty lines that must not differ — the defect ⑭ spent a rung removing —
    // and because the node must exist for exactly one guest in exactly one run. Dom 2 gets no node,
    // which is what lets the witness say "the PEER ran to completion".
    if boot == LinuxBoot::UnmappedFault && slot == 0 {
        let anchor = "\n\tapb-pclk {";
        if !rendered.contains(anchor) {
            eprintln!(
                "xtask {task}: {src} has no `apb-pclk` node to anchor the fault probe against — \
                 the fault-probe boot would describe a machine with nothing to fault on, and would \
                 pass by doing nothing."
            );
            return None;
        }
        let node = format!(
            "\n\tfault-probe@{addr:x} {{\n\t\tcompatible = \"arm,pl011\", \"arm,primecell\";\n\t\t\
             reg = <0x00 0x{addr:x} 0x00 0x1000>;\n\t\tclocks = <0x8000 0x8000>;\n\t\t\
             clock-names = \"uartclk\", \"apb_pclk\";\n\t}};\n",
            addr = FAULT_PROBE_ADDR
        );
        rendered = rendered.replacen(anchor, &format!("{node}{anchor}"), 1);
    }

    // ── the peer-LOOP probe (dom 1 only) ────────────────────────────────────────────────────────
    //
    // Same instrument as ③-b2b-ii-d's peer-probe node, just MANY of them. Each names an AMBA
    // peripheral inside the peer's RAM, so dom 1's own bus scan faults on the peer 48 times per node
    // and crosses `MAX_PEER_FAULTS` — the guest is doing the looping, not EL2 simulating it.
    //
    // **Dom 2 keeps its single node and its 48 faults, far under the cap**, which is what lets the
    // witness say the peer ran to completion. Addresses start one page above the peer's base so they
    // do not collide with the peer-probe node already there.
    if boot == LinuxBoot::PeerLoop && slot == 0 {
        let anchor = "\n\tapb-pclk {";
        if !rendered.contains(anchor) {
            eprintln!(
                "xtask {task}: {src} has no `apb-pclk` node to anchor the peer-loop probes against \
                 — the peer-loop boot would never cross the cap and would pass by doing nothing."
            );
            return None;
        }
        let base = peer_of(slot).ram_base;
        let mut nodes = String::new();
        for i in 1..=PEER_LOOP_NODES {
            let addr = base + i * 0x1000;
            nodes.push_str(&format!(
                "\n\tpeer-loop@{addr:x} {{\n\t\tcompatible = \"arm,pl011\", \"arm,primecell\";\n\t\t\
                 reg = <0x00 0x{addr:x} 0x00 0x1000>;\n\t\tclocks = <0x8000 0x8000>;\n\t\t\
                 clock-names = \"uartclk\", \"apb_pclk\";\n\t}};\n"
            ));
        }
        rendered = rendered.replacen(anchor, &format!("{nodes}{anchor}"), 1);
    }

    let suffix = match boot {
        LinuxBoot::Shipped => "",
        LinuxBoot::UnmappedFault => "-fault",
        LinuxBoot::PeerLoop => "-peerloop",
        // ⑲-1: byte-identical device trees to the shipped boot — the guests must not be able to
        // tell they are on a machine with an SMMU, which is the point.
        LinuxBoot::Smmu => "",
    };
    let dts_out = dir.join(format!("guest-dom{dom}{suffix}.dts"));
    let dtb_out = dir.join(format!("guest-dom{dom}{suffix}.dtb"));
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
/// * **`  DMA      [mem 0x0000000048000000-0x0000000063ffffff]`** (two leading spaces, which are
///   part of the marker) — THE MEMORY CONTRACT, in one
///   string. It is the kernel reporting the window it got from our DTB, and it must equal what the
///   emitter maps for **this domain** and the `-device loader` addresses above (where the blobs
///   land). Four places that must agree; this is the assertion that goes red when they stop.
///
///   **It ends at `0x63ffffff`, not `0x7fffffff`, since ③-b2a split the window** — the running
///   kernel is dom 1 and owns `LINUX_RAM_BASE..LINUX_RAM_SPLIT`, dom 2 the upper half. Note that
///   `xtask doc-markers` does NOT scan `.rs` files, only `docs/*.md`, so a stale marker quote in
///   THIS doc comment is caught by a human reading the diff or not at all — which is how the
///   `0x7fffffff` above survived one rung too long.
///
///   ⚠ **It was `node   0: [mem …]` until ⑲-3a, and the swap is not cosmetic.** That rung reserved
///   the top 2 MiB of each window `no-map`, and Linux responds by SPLITTING its node-0 range in two
///   (`…48000000-63dfffff` and `…63e00000-63ffffff`) — so the single string that used to carry the
///   whole window stopped existing. The zone span is the same four-way agreement in a form the
///   reservation does not perturb: zone ranges include their holes. **Do not read the swap as a
///   weakening — read it as the one line here that still names both ends of the window.** The pad
///   itself is asserted separately, by the `OF: reserved mem: …` marker.
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
    "  DMA      [mem 0x0000000048000000-0x0000000063ffffff]",
    // ⑲-3a — the kernel-side half of the landing-pad claim, and the half that makes the EL2-side
    // `dmapad OK` mean something. Linux read the `reserved-memory` child out of OUR device tree,
    // agreed the range, and says `nomap`: it mapped nothing there. It then drops the range from
    // `System RAM` entirely, which is what moved the two `baleen-guest-ram` markers below.
    "OF: reserved mem: 0x0000000063e00000..0x0000000063ffffff (2048 KiB) nomap non-reusable dma-pad@63e00000",
    "baleen: linux PSCI FID 0x84000006 -> NOT_SUPPORTED",
    "Run /init as init process",
    // Userspace, out of our initramfs.
    "########## BALEEN-STEP0-OK ##########",
    // ⑲-3a: ends at `63dfffff`, not `63ffffff` — the top 2 MiB is the `no-map` landing pad, and the
    // kernel does not count it as System RAM at all. Userspace reporting the SHORTENED range is the
    // reservation observed from the far end of the guest: not just parsed at boot, but reflected in
    // what `/proc/iomem` tells a process the machine has.
    "baleen-guest-ram: 48000000-63dfffff:SystemRAM",
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
    // `[dom 2] baleen-guest-ram: 64000000-7fdfffff` is the strongest single assertion in this file:
    // it is dom 2's userspace reading dom 2's `/proc/iomem`, which requires dom 2's kernel to have
    // parsed dom 2's DTB and reached that RAM through dom 2's OWN Stage-2 image. Guest A cannot
    // produce that string — its window ends at 0x63dfffff, and the peer's half is unmapped in its
    // image (`peer OK`, walked from the descriptors before either guest ran).
    // ⑲-3a moved the top end from `7fffffff` to `7fdfffff`: the last 2 MiB is the `no-map` landing
    // pad, which Linux excludes from System RAM. The string got STRONGER — it now names dom 2's
    // window and dom 2's reservation at once, and neither guest can print the other's.
    // Dom 2's KERNEL lines cannot be asserted tag-plus-content: `printk` puts its own timestamp
    // between the two (`[dom 2] [    0.000000] Linux version …`), and the timestamp varies. So the
    // kernel-side claim is made by CONTENT that only dom 2 can print — its `/memory` window — and
    // the tag-plus-content claims are the two userspace lines, which carry no timestamp.
    "  DMA      [mem 0x0000000064000000-0x000000007fffffff]",
    // ⑲-3a — dom 2's own reservation, at ITS window's top. Two guests, two device trees, two
    // kernels each honouring the range its own DTB named.
    "OF: reserved mem: 0x000000007fe00000..0x000000007fffffff (2048 KiB) nomap non-reusable dma-pad@7fe00000",
    "[dom 2] ########## BALEEN-STEP0-OK ##########",
    "[dom 2] baleen-guest-ram: 64000000-7fdfffff:SystemRAM",
    // ★ ⑱-4b-i, and these two are the GUEST-OBSERVED half of that rung — the only assertion in this
    // list that a guest which went idle was given the pCPU back.
    //
    // `baleen: idle OK` is EL2's account: it counted the blocks and the wakes and they balanced.
    // These are the kernels' account, and the two can disagree in the direction that matters. EL2
    // issuing a `SchedWake` says the MODEL made a vCPU runnable; only the guest printing the line
    // AFTER its `sleep` says the kernel actually resumed and ran userspace again. A wake that the
    // scheduler records but never acts on would leave `idle OK` green and these absent.
    //
    // Requiring END and not START is deliberate: START proves nothing (it precedes the idling), and
    // a boot that prints START without END is precisely a starved guest, which is what the kill
    // probe produces.
    "[dom 1] ########## BALEEN-IDLE-END ##########",
    "[dom 2] ########## BALEEN-IDLE-END ##########",
    // ★★ ⑱-6 — **THE GUEST'S OWN ACCOUNT OF WHICH OF ITS CPUs TOOK AN INTERRUPT IT RE-AIMED.**
    //
    // `guest-init.sh` writes CPU1's mask to the `uart-pl011` IRQ's `smp_affinity`, which makes
    // arm64 Linux write `GICD_IROUTER<33>` into hv-metal's emulated distributor. EL2 then injects
    // INTID 33 **from a vCPU the routing does not name**, so honouring the register and ignoring it
    // lead to different CPUs — and this line is the kernel saying which one actually ran the
    // handler.
    //
    // ⚠ **`cpu0=0` carries as much of the property as `cpu1=1`.** The removed-fix probe
    // (`spi-route-probe`) produces `cpu0=1 cpu1=0`: same one interrupt, same guest, delivered where
    // the pCPU was instead of where the guest aimed it. Asserting the whole string is what makes
    // this a discriminator rather than a count.
    //
    // ⚠ And note what this is NOT: `baleen: vspi OK` is EL2's account of its own routing decision.
    // These are the *kernels'*, produced by their interrupt paths, and neither takes the other's
    // word for where the interrupt went.
    "[dom 1] baleen-spi-counts: cpu0=0 cpu1=1",
    "[dom 2] baleen-spi-counts: cpu0=0 cpu1=1",
    // ⑱-6's two preconditions, asserted rather than assumed — both are ways the line above could go
    // green for the wrong reason.
    //
    //   * `baleen-spi-intid: 33` binds the INTID the GUEST reports for its UART to `WITNESS_SPI` in
    //     `linux.rs`. Change one without the other and EL2 would be injecting an interrupt the guest
    //     never re-aimed. Only the INTID is asserted; Linux's own IRQ number follows it in
    //     parentheses because that allocation may legitimately move.
    //   * `baleen-spi-affinity: 2` says the kernel ACCEPTED the affinity write. A write that silently
    //     failed would leave the route on CPU0, and `cpu0=0 cpu1=1` would then be unreachable for a
    //     reason that has nothing to do with routing — a red gate blaming the wrong mechanism.
    // ★★ ⑱-7 — **THE VICTIM'S ACCOUNT, and the interrupt axis's counterpart to the peer probe.**
    //
    // **Only dom 1 raises the CPU-backtrace IPI** (`sysrq l` in `guest-init.sh`), so dom 1 ends with
    // its own **1** and dom 2 — which nothing in the machine raises this INTID for — must end with
    // **0**.
    //
    // ⚠ **What the `no-irq-confinement` probe actually does to this line is ABSENT it, not flip it,
    // and the difference is measured rather than predicted.** Dom 2 wedges under the foreign IPI
    // traffic (`rcu_preempt detected stalls`, no progress for 573 s) and never reaches its own
    // report. So this marker goes red by the victim's *death*, which is a coarser kill than the
    // 0-vs-1 it was designed for. The clean counted leak under that probe is `baleen-spi-counts:`
    // reading `cpu1=2` — see `docs/INTERRUPT-CONFINEMENT.md` §4.
    //
    // ⚠ **One sender, not two, and that is load-bearing rather than tidy.** EL2's cross-vCPU delivery
    // goes through a `PendingSet`, which is a SET: a leaked INTID the victim also raises for itself
    // coalesces into one entry and vanishes. With both guests sending, the discriminator would be
    // 1-vs-2 on a quantity that cannot reliably reach 2 — MEASURED, probe armed, both sending: dom 1
    // read 0 and dom 2 read 1. `[dom 2] … : 0` is the assertion that carries the property.
    //
    // ⚠ This asserts something a guest says about ANOTHER guest's containment, which no EL2 marker
    // can: `baleen: irqconfine OK` is EL2 reporting that it refused, and this is the party that
    // would have been disturbed reporting that it was not.
    // ⑳-d: the scrub's maintenance stride, measured. Asserted as PRESENT (the OK form) rather than
    // as a fixed 64, because a core with a finer line is handled CORRECTLY here — the stride simply
    // gets finer — and pinning the number would fail a machine this code gets right.
    "baleen: scrubline OK: the frame-scrub maintenance loop strides ",
    "[dom 1] baleen-ipi6-total: 1",
    "[dom 2] baleen-ipi6-total: 0",
    "[dom 1] baleen-spi-intid: 33 ",
    "[dom 2] baleen-spi-intid: 33 ",
    "[dom 1] baleen-spi-affinity: 2",
    "[dom 2] baleen-spi-affinity: 2",
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
    // ★ ③-b2b-ii-e — **EL2 OWNS A CLOCK.** Until this rung every re-entry to EL2 on this path was
    // caused by the guest: a trap it took, or the arch-timer PPI it programmed for itself. That is a
    // behavioural guarantee, and it already failed once — ③-b2b-ii-c2 put a machine-freezing hang on
    // `main` whose own PR run was green. `HCR_EL2.TWI` patched the case that bit, and was itself
    // behavioural. Now EL2 arms its own hypervisor timer (`CNTHP_*_EL2`, PPI 26) for one 10 ms slice
    // on every switch-in, and THAT — not the guest's tick — is what preempts. The guest cannot
    // program it (EL2-only registers), cannot mask it (③-b1 took the physical distributor away, and
    // an IRQ routed to EL2 by `HCR_EL2.IMO` is not maskable by EL1's `PSTATE.I`), and cannot outlast
    // it (the deadline is absolute).
    //
    // The assertion is a read-back plus a floor, and neither is a count of what the guests did. The
    // read-back is `CNTHP_CTL_EL2` itself, in the shape `wfi OK` established. The floor is expiries
    // against elapsed time — a quantity EL2's own deadline determines and no guest contributes to —
    // which reads ZERO on the build this rung replaces. What is deliberately NOT asserted is a bound
    // on how long a guest held the pCPU: a cooperative guest satisfies any such bound with EL2's
    // clock switched off entirely, so it would pass unchanged on `main` (design-lesson #105). That
    // claim belongs to the probes, recorded at `report_el2_slice`: with `HCR_EL2.TWI` off AND one
    // guest's tick forwarding cut — no trap, no tick, no yield, nothing cooperative left — the peer
    // must still boot and power off.
    "baleen: slice OK: EL2 re-enters the machine on ITS OWN clock — CNTHP_CTL_EL2 read back as",
    "baleen: EL2 arms a clock of its OWN — CNTHP_EL2 at 100 Hz on PPI 26",
    // ③-b2b-ii-c2 follow-up: an idle guest YIELDS the pCPU. Asserted as a READ-BACK of `HCR_EL2`,
    // not as a count of trapped WFIs — with two kernels sharing one pCPU neither is ever short of
    // work, so a boot in which nobody goes idle has a count of zero and is perfectly good.
    // (Measured: a run of this gate did exactly that, and an earlier version of the witness refused
    // it.) The read-back is true on every boot and cannot be satisfied by luck.
    //
    // ⚠ **③-b2b-ii-e DEMOTED what this marker means, and the old wording is left behind on purpose.**
    // It used to say that without `TWI` the peer never runs again and both guests freeze — true when
    // this was the only way EL2 could get the pCPU back. EL2 now owns a clock, so a `TWI` that
    // stopped working costs a wasted slice rather than the machine.
    //
    // The same rung's probes also corrected the converse, which is the more surprising half: `TWI`
    // never covered for a missing EL2 clock either. MEASURED — with EL2's clock disarmed and `TWI`
    // in force, the two kernels do not time-slice at all. They run strictly sequentially, one
    // handover in the whole boot, at `SYSTEM_OFF`: a guest that always has work never executes
    // `wfi`, so the yield simply never fires. The concurrency this gate has been asserting since
    // ③-b2b-ii-c2 came from the every-eighth-tick preemption, and now comes from `CNTHP_*_EL2`.
    "baleen: wfi OK: HCR_EL2.TWI is in force (HCR_EL2 read back as",
    // ★ ⑱-1 — **THE GUEST'S IDENTITY IS EL2'S CHOICE.** A guest's `MPIDR_EL1`/`MIDR_EL1` reads are
    // served by `VMPIDR_EL2`/`VPIDR_EL2`, both **UNKNOWN at reset**, and hv-metal wrote neither.
    // MEASURED on QEMU 11.0.3 before the rung: they hold the physical values, which are exactly what
    // the guests' device trees describe — correct by the implementation's reset choice rather than by
    // anything the hypervisor did. This rung makes the value a function EL2 evaluates.
    //
    // ⚠ The value is UNCHANGED, so no guest behaviour witnesses it and none is claimed. The assertion
    // is the structural one: both registers read back as what EL2 wrote, on EVERY entry to EL1 —
    // false on `main`, where the write does not exist. Non-vacuity was PROBED, not argued: writing
    // `Aff0 = slot` instead of `Aff0 = vCPU` gives dom 2 an MPIDR its own `cpu@0 { reg = <0x00>; }`
    // does not describe, and dom 2 must then fail to boot.
    "baleen: identity OK: every entry to EL1 carries an identity EL2 CHOSE",
    // ★★ ⑱-4b-i — **AN IDLE vCPU LEAVES THE SCHEDULER'S CANDIDATE SET.** `handle_linux_wfi` issued
    // `SchedPreempt` — `Running -> Runnable` — for a vCPU that had just said it had nothing to do.
    // The model has the right word for that (`Blocked`) and this port was not using it.
    //
    // ⚠ **MEASURED ON `main`, not argued.** With `guest-init.sh`'s sleep in place and `SchedPreempt`
    // still there, dom 1 and dom 2 trapped **8,735 `wfi`s each and yielded on every one** — counts
    // identical to the unit, the signature of perfect alternation — for **17,613 context switches**
    // against 72 per guest on a boot that never idles. Each guest went idle, was handed the pCPU by
    // a peer that was also idle, and handed it straight back. It is a 122x pathology rather than a
    // hang, which is exactly why it survived this long: the guests' own ticks keep breaking the
    // cycle, so the wall clock looks fine. Safe by workload, not by construction.
    //
    // Two identities are asserted IN hv-metal, which parks on either: `readback == blocked` (the
    // model itself reports the vCPU as `Blocked`, not merely that EL2 asked for it) and
    // `woken == blocked` (liveness — nothing was put to sleep and abandoned). Both are vacuously
    // true at zero, which is why non-vacuity lives HERE instead: `idle OK` is printed only when
    // something was actually blocked, so requiring the string is what makes the witness non-empty.
    //
    // ⚠ **Requiring it in THIS list and not the fault lists is load-bearing, and was measured.**
    // Blocking needs a peer, and the fault configurations kill dom 1 — so dom 2 idles alone, takes
    // `wait_at_el2` every time and blocks zero times. That is a correct boot. An earlier version
    // asserted `blocked > 0` inside hv-metal, which parked EL2 on the fault boot and hung it to a
    // 300 s timeout; the count is a claim about the workload, and the workload differs per config.
    //
    // ⚠ The yield counts are REPORTED, never asserted — the collapse from 8,735 is the headline but
    // its exact value is tick rates and luck (design-lesson #127). And the reverse probe, restoring
    // `SchedPreempt`, does NOT kill: the machine still works, just far harder. The probe that kills
    // is deleting the waker, which starves a sleeping guest — and that probe only became usable
    // because of the sleep, since it cannot fire on a boot that never idles.
    "baleen: idle OK: a vCPU that executed WFI left the scheduler's candidate set and came back",
    // ★★ ⑱-4b-ii — **THE SECOND vCPU EXECUTES.** `PSCI CPU_ON` seeds a secondary's context, admits
    // it to hv-core, and the guest's own kernel reports two processors activated.
    //
    // ⑱-3b-ii's version of this marker asserted `DISPATCHED_NONBOOT == 0` — no vCPU but the boot one
    // ever reached the pCPU — which was right while nothing could start one and is false BY DESIGN
    // now. It is REPLACED, not relaxed, by the two statements it stood in for:
    //
    //   * `seeded == admitted` — EL2 never made a vCPU eligible to run without first giving it a
    //     context. The hazard was never "a non-boot vCPU", it was an UNSEEDED one, measured at
    //     ⑱-3b-ii as `EC=0x20 ELR=FAR=0x0` and a boot that never finished.
    //   * `nonboot_offline == nonboot` — every secondary is Offline once its domain retires. ⚠ This
    //     conjunct was DELIBERATELY WEAK in ⑱-3b-ii, which said so, and is now LOAD-BEARING: with a
    //     secondary actually running, a domain that retires only its running vCPU leaves a sibling
    //     Runnable, and the scheduler keeps handing the pCPU to a retired guest's parked vCPU while
    //     the peer starves.
    //
    // The dispatch count is the rung's headline and is REPORTED, never asserted — a guest that never
    // calls CPU_ON produces zero, and that is a correct boot (design-lesson #127).
    "baleen: vcpus OK: each of the",
    // ★★ ⑱-4b-ii — **THE KERNEL'S OWN ACCOUNT, and it is stronger evidence than EL2's.**
    //
    // `baleen: vcpus OK` is EL2 saying it seeded and admitted a secondary. This is a real Linux
    // kernel saying the secondary CAME UP AND RAN — it brought it online, ran a task on it, and
    // counted it. EL2 can be wrong about the first in a way that leaves this absent.
    //
    // ⚠ **The FORBIDDEN twin below is what makes the pair complete, and it is why this one can be
    // an unprefixed substring.** `serial.contains` matches anywhere, so this string proves only that
    // AT LEAST ONE guest activated two CPUs — a per-dom form is unwritable because the console
    // prefix and the message are separated by a variable `[    N.NNNNNN]` timestamp. The twin closes
    // that gap from the other side: `SMP: Total of 1 processors activated.` appears the moment
    // EITHER guest fails, so requiring one and forbidding the other pins both.
    "SMP: Total of 2 processors activated.",
    // ★ ⑱-5 — **AN SGI IS DECODED UNDER THE FENCE AND ROUTED BY TARGET.** `ICC_SGI1R_EL1` names its
    // targets by physical affinity, which is why the architecture traps it to EL2 at all. hv-metal
    // used to read bits [27:24] only — the INTID — and its own doc admitted the affinity fields were
    // "deliberately not read, because with a single vCPU there is no other target they could name".
    //
    // MEASURED on a reverted probe once a second vCPU actually ran: every IPI landed on whichever
    // vCPU was running, giving `SMP: failed to stop secondary CPUs 1` and a boot-gate TIMEOUT. That
    // is why this rung lands BEFORE the one that starts a second vCPU.
    //
    // The marker asserts a conservation identity — every `(write, target)` pair the decode names gets
    // exactly one disposition — which is a property of the routing loop's three exits and not of
    // anything a guest sends. The claim that the decode names the RIGHT targets is five Kani
    // harnesses over `hv_vdev::sgi` (∀ 64-bit value a guest can write) plus their four kill probes;
    // no boot can make it, because one runnable vCPU only ever names itself.
    "baleen: sgiroute OK: dom 1's SGIs are decoded under the fence and ROUTED BY TARGET",

    // ★ ③-b2b-ii-f — **THE FP/SIMD REGISTER FILE IS PER-GUEST.** The last enumerated member of the
    // "state the hardware does not swap" class, and the one that stayed open longest: `v0..v31`,
    // `FPCR` and `FPSR` are one physical file shared by every context on the CPU, and nothing saved
    // them. `CPACR_EL1` IS saved, which is what made the leak reachable rather than latent — a guest
    // resumes with its own trap state permitting FP while its kernel still believes the live
    // registers hold its current task's data, and reads whatever the peer left.
    //
    // MEASURED both ways before the fix existed: with `CPTR_EL2.TFP` set, dom 1 took 15 FP traps and
    // dom 2 took 16, EVERY one of them the guest's first FP use after a switch-in with its own
    // `CPACR_EL1` allowing it; and the shipped witness reports the file holding the PEER's data at
    // 12 switch-ins per guest.
    //
    // The assertion is the READ-BACK, not that count: `verified == switches` must hold on every boot
    // whatever the guests do, and it catches the failure this rung can actually have — a PARTIAL
    // restore, which on a boot that never touches the high registers is indistinguishable from a
    // correct one. The foreign-data count is reported beside it and never asserted, because two
    // guests that avoid floating point leave it at zero on a perfectly good boot (design-lesson #127).
    //
    // ⚠ THE KILL PROBE DOES NOT KILL, which is why this marker carries more weight than most.
    // Deleting the FP restore leaves both kernels reaching userspace with no panic and no trap —
    // Linux's own lazy-FP reload usually overwrites the clobbered file before anything reads it — so
    // this read-back is the ONLY thing between a broken restore and a silent green boot.
    "baleen: fp OK: dom 1 resumed on its OWN FP register file every time —",
    "baleen: fp OK: dom 2 resumed on its OWN FP register file every time —",
    // ★★ ⑱-4a — **THE VIRTUAL ACTIVE PRIORITIES ARE PER-vCPU.** `ICH_AP0R<n>_EL2`/`ICH_AP1R<n>_EL2`
    // hold the priorities a vCPU has acknowledged and not yet ended; while a bit is set the virtual
    // CPU interface signals nothing at or below that level. They are the same class of state as the
    // list registers and `ICH_VMCR_EL2` — one physical interface, no hardware swap — and they were
    // the one member of that class `gic::VgicCtx` did not carry, across every arc since 7c.
    //
    // ⚠ **FOUND BY MEASUREMENT, NOT BY READING THE REGISTER LIST**, and the diagnosis it replaced
    // was confidently wrong. The recorded blocker for a guest's second vCPU was "EL2 presents CNTV
    // only to whoever holds the pCPU, so a deadline that expires while descheduled is never
    // delivered". Six instrumented boots refuted it: the tick ARRIVES once per slice per vCPU
    // forever, `TIMER_FORWARDED` is frozen only because `inject_hw` fails against a bank holding
    // FOUR Pending vINTID 27, and the guest cannot acknowledge any of them because
    // `ICH_AP1R0_EL2` is stuck at 0x10000 — bit 16, priority 0x80, which is every interrupt this
    // port injects — inherited from its sibling. Saving and restoring these two registers is the
    // entire fix; a competing theory (refuse DUPLICATE ticks) was implemented and REFUTED in one
    // boot, the bank stopped filling and the guest stayed wedged.
    //
    // The assertion is the READ-BACK — `verified == switches`, structural on every boot — and NOT
    // the leak count, which measured 0, 0, 1, 1 per guest across four consecutive boots of this
    // configuration. The condition is real here and it is also a coin toss; a gate on it would be
    // red half the time (design-lesson #127).
    //
    // ⚠ **THE KILL PROBE DOES KILL, and loudly.** Unlike ③-b2b-ii-f's, dropping the restore is not
    // silently survivable: see the rung's probe table. The poison is what makes that true on THIS
    // configuration — all priorities set active between save and restore, so an unrestored bank is
    // a guest that can take no interrupt at all.
    "baleen: vapr OK: dom 1 resumed on its OWN virtual active priorities every time —",
    "baleen: vapr OK: dom 2 resumed on its OWN virtual active priorities every time —",
    // ⑰-a — the boot transcript records what THIS BUILD believes a vCPU context is made of, so a
    // component silently added or removed changes a line the gate asserts. The real obligation is
    // the compiler's: `save`, `restore` and `poison` each destructure the context with no `..`, so
    // a forgotten component is E0027 and a component named-but-not-acted-on is `unused_variables`
    // under `metal-lint`'s `-D warnings`. That is what makes the class of bug which kept `v0..v31`
    // unsaved from M5 Arc 1 to ③-b2b-ii-f unexpressible rather than merely unlikely.
    //
    // This marker is the transcript half, in the same spirit as the register list it extends: it
    // cannot enforce anything, it records. Asserting the COUNTS is deliberate — adding a register or
    // a component is meant to redden here and be updated knowingly, which is the `perguest OK`
    // discipline applied to the context.
    "baleen: vcpu context = 4 components (gprs sysregs vgic fp) / 25 registers:",
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
    // ★ The pending-set rung's discriminating witness, and the ONE marker here that asserts a
    // property the shipped guest cannot demonstrate on its own. Before it, a guest that filled the
    // list-register bank reached `crate::park()` — and it could: mask interrupts, then write
    // `ICC_SGI1R_EL1` five times with distinct ids, and the whole machine stops, PEER DOMAIN
    // INCLUDED. Alpine issues 59 SGIs a boot and takes them all, so the bank never fills and a
    // counter-based witness would read zero on a good boot. The probe manufactures the condition
    // instead, and every clause below is a READ-BACK: the bank really refuses, the overflow lands in
    // the set, and `ICH_HCR_EL2.UIE` is read back armed and then clear.
    "baleen: lroverflow OK: a FULL list-register bank now DEFERS instead of halting",
    // ★ The LAST guest-reachable halt on this path, closed. A guest that fills its four list
    // registers with SGIs it never takes made the next timer forward fail — and that used to
    // `park()`, killing the peer too. Measured before the fix: `sgis_placed=4
    // timer_forward_refused=true`. The shipped guest never fills its bank, so the probe manufactures
    // the condition; the marker is what says it really did.
    "baleen: tickdefer OK: a FULL list-register bank DEFERS the forwarded timer instead of halting",
    // ⑲-3a — EL2's half of the landing-pad claim: the sentinel it wrote into each guest's reserved
    // range before the first `eret` is still there after both kernels ran to userspace and powered
    // off. On its own this is only consistent with the reservation being honoured — the half that
    // says Linux SAW the range is the pair of `OF: reserved mem: …nomap…` markers ABOVE, one per
    // guest. Matched up to the addresses, which are the part that varies.
    "baleen: dmapad OK: every guest booted an unmodified Linux to userspace and powered off \
     without writing one byte of the 2048 KiB its device tree reserves no-map at the top of its \
     own window",
];

/// What the **fault-probe** boot must show, and it is the whole rung in five lines.
///
/// Dom 1's own driver core touches a node describing a peripheral at an address in no window, taking
/// a Stage-2 abort EL2 has no rule for. Before this rung that parked the machine and dom 2 — which
/// did nothing — died with it. Now dom 1 is retired and **dom 2 runs to completion and powers off**.
///
/// **Every one of these is load-bearing.** Without the `RETIRED` line the fault never happened and
/// the probe is inert; without dom 2's `SYSTEM_OFF` the peer did not survive, which is the entire
/// claim; and `retire dom 1: RETIRED FOR A FAULT` is what stops a killed domain being reported as a
/// clean shutdown — the witness-that-lies this rung had to avoid.
///
/// ⚠ **`every real Linux guest has powered off` is deliberately ABSENT**, and its absence is checked
/// by `LINUX_FAULT_FORBIDDEN`: a boot in which a domain was killed must not claim they all shut down.
const LINUX_FAULT_MARKERS: &[&str] = &[
    "baleen: guest FAULT: EC=0x24 data abort outside every emulated device",
    "baleen: dom 1 RETIRED —",
    "baleen: retire dom 1: RETIRED FOR A FAULT — it was stopped and the machine kept running",
    "baleen: retire dom 2: powered off cleanly",
    "baleen: dom 2 issued PSCI SYSTEM_OFF — a real Linux kernel booted and shut down on hv-metal's EL2",
];

/// What the **peer-loop** boot must show: a guest retired for LOOPING, and its peer unharmed.
///
/// The ninth guest-reachable halt, and the one the sweep missed. `handle_peer_fault` capped repeated
/// peer faults at `MAX_PEER_FAULTS` and **parked the machine** on exceeding it — reachable with a
/// two-instruction loop, killing the innocent peer. Here dom 1's device tree carries
/// `PEER_LOOP_NODES` probe nodes so its own bus scan crosses the cap; dom 1 is retired and dom 2
/// powers off.
///
/// The `guest FAULT:` prefix is asserted deliberately: the diagnostic used to say `LINUX GUEST TRAP`,
/// which is the FORBIDDEN marker meaning "EL2 hit something fatal". A guest looping is not that.
const LINUX_PEER_LOOP_MARKERS: &[&str] = &[
    "baleen: guest FAULT: dom 1 has faulted on dom 2's memory",
    "baleen: dom 1 RETIRED — looped on its peer's memory",
    "baleen: retire dom 1: RETIRED FOR A FAULT — it was stopped and the machine kept running",
    "baleen: retire dom 2: powered off cleanly",
    "baleen: dom 2 issued PSCI SYSTEM_OFF — a real Linux kernel booted and shut down on hv-metal's EL2",
];

/// Strings the fault-probe boot must NOT show, on top of [`LINUX_FORBIDDEN`].
///
/// The summary line claims every guest powered off. One of them was KILLED, so a build that still
/// printed it would be reporting a clean two-kernel shutdown for a boot where a kernel was retired —
/// exactly the conflation `Retirement` exists to prevent, and the reason `end_of_boot` gates that
/// line on every slot being `PoweredOff`.
const LINUX_FAULT_FORBIDDEN: &[&str] = &[
    "baleen: every real Linux guest has powered off",
    "baleen: dom 1 issued PSCI SYSTEM_OFF",
];

/// ★ **⑲-1's corpus: the shipped real-Linux boot PLUS the SMMU's own markers, in ONE boot.**
///
/// ## Why this list is a concatenation and not a new set
///
/// The rung's whole claim is that co-locating the two halves changes NEITHER. So the guest half is
/// [`LINUX_MARKERS`] **entire** — same guests, same device trees, same witnesses, byte for byte —
/// and the device half is the SMMU's rung-1/2 markers, which `boot-test.sh` already asserts in the
/// `smmu` configuration. If either half needed weakening to sit beside the other, the concatenation
/// would fail and that would be the finding.
///
/// ## What the SMMU markers mean here, and the one that is load-bearing
///
/// * **rung1 DEFAULT-DENY** — the SMMU aborts a real bus master's DMA before `SMMUEN`.
/// * **rung2 THROUGH-STE** — the POSITIVE control, and without it the denials are vacuous: the same
///   device, bound to a bypass STE, DMAs successfully. A wrong `LOG2SIZE`, a mis-aligned
///   `STRTAB_BASE` or a StreamID that is not the device's RequesterID makes *everything* "abort",
///   which would look like flawless isolation.
/// * **rung2 STREAM-TABLE / STREAMID-SPECIFIC / OUT-OF-RANGE** — the denials proper, each with the
///   SMMU's own event-queue record naming the offending StreamID.
///
/// ⚠ **What this configuration does NOT assert, stated so the corpus is not read as more than it
/// is.** Rungs 3 and 4 — a device confined to a *domain's* `p2m` — do not run here; they are
/// synthetic-configuration apparatus that cannot coexist with real guests (two collisions, both
/// recorded on `dmawitness::witness`). So this boot shows an SMMU that denies by default *beside* two
/// isolated kernels; it does **not** yet show a device confined to a real guest's memory. That is
/// ⑲-2, and conflating the two would be exactly the altitude error the ledger warns about.
///
/// ## ★★ THIS RUNS ON CI — and ⑲-1 concluded it could not, from one register read
///
/// ⑲-1 put this boot in the required gate, watched it go red with
///
/// ```text
/// baleen: smmu rung1 DEFAULT-DENY FAIL (present=true aborting=true stage2=false idr0=0x0d44101a …)
/// ```
///
/// and concluded that **the runner's QEMU cannot do SMMUv3 stage-2**, moving the boot to a local-only
/// task. **That was wrong, and the error is worth more than the fix.** QEMU's SMMUv3 advertises
/// stage-2 **only when asked**: `arm-smmuv3.stage` is `"1"` — stage-1 only — by DEFAULT, and has
/// existed since QEMU **8.1** (merged 2023-05). The runner has **8.2.2**. The capability was there
/// all along; nothing was requesting it. **A missing capability was inferred from an unrequested
/// one, on a single `IDR0` read** — and it nearly bought a staleness tripwire for coverage that was
/// available for one command-line flag.
///
/// MEASURED with `-global arm-smmuv3.stage=2`, on the runner: **all five markers below found**,
/// `DEFAULT-DENY` included, in a 4-configuration `qemu-linux-test`.
///
/// ★ **So the SMMU rungs (#91–#95) are CI-GATED FOR THE FIRST TIME** — hardware witness as well as
/// proofs. Before this, `iommu=smmuv3` had never appeared in a CI run at all: `boot-test.sh`'s
/// `"smmu"` entry passes `-device edu` with **no IOMMU** and asserts the no-SMMU positive control.
/// The proofs were always required-gated (20 Kani harnesses); it is the *boot* that was missing.
///
/// ## ★ THE PROBE, and it killed harder than predicted/// ## ★ THE PROBE, and it killed harder than predicted
///
/// | probe | predicted | measured |
/// |---|---|---|
/// | drop `iommu=smmuv3`, keep the `smmu` binary | the SMMU markers redden, the guest half stays green | **the WHOLE boot dies** — `EC=0x25` data abort at EL2, `FAR=0x09050044` |
///
/// `0x0905_0044` is the SMMU's own MMIO window. A binary built with `smmu` probes for an SMMU at
/// boot, and on a machine without one it takes an **external abort at EL2** before Linux is ever
/// entered. **So the binary and the machine are a matched pair, and mismatching them is fatal early
/// rather than degrading** — worth knowing before anyone assumes the feature is inert on a plain
/// `virt`. It also means the guest half of this corpus cannot fail *independently* of the device
/// half in that direction, which is why the probe is recorded with what it actually showed rather
/// than with the tidier result that was expected.
const LINUX_SMMU_MARKERS: &[&str] = &[
    "baleen: smmu rung1 DEFAULT-DENY",
    "baleen: smmu rung2 THROUGH-STE",
    "baleen: smmu rung2 STREAM-TABLE",
    "baleen: smmu rung2 STREAMID-SPECIFIC",
    "baleen: smmu rung2 OUT-OF-RANGE",
    // ★★ ⑲-2 — the arc's point: a bus master confined by a REAL guest's own proven map.
    //
    // Rungs 1/2 above are about the SMMU itself and rung 3 (synthetic-config only) proves
    // confinement to a domain built for the test. THIS one binds the device to `S2TTB` = the very
    // table `VTTBR_EL2` carries for a domain running an unmodified Alpine kernel, under that
    // domain's VMID, and shows the device reaches that guest's memory and is ABORTED on its peer's.
    //
    // ⚠ Two things it does NOT claim, both stated on `dmawitness::witness_real_guest`: the positive
    // arm is a CONTROL only (real guests are identity-mapped, so it cannot separate "translated"
    // from "passed through" — that is rung 3's, on a non-identity map); and this is CONFINEMENT,
    // not SIMULTANEITY — nothing runs while THIS device DMAs. Ledger item 2(b) is closed by the
    // `dmaflight OK` marker below, not by this one.
    "baleen: smmu realguest OK",
    // ★★ ⑲-3b — the same confinement, IN FLIGHT ACROSS GUEST EXECUTION, which closes honest-ledger
    // item 2(b). Every DMA result before this one was taken with the machine quiesced around the
    // device; this one is kicked 200 exits into a running pair of kernels and observed from the exit
    // path. ⚠ It claims "in flight across guest execution", NOT wall-clock concurrency — one pCPU
    // under TCG cannot support the stronger sentence, and `report_dma_inflight`'s docs say so.
    //
    // ★ The binding is DERIVED, not written: one `DeviceAssign` through the proven dispatch, then
    // re-derived from the model by `teardown::dispatch` on every dispatch for the whole flight. A
    // hand-poked STE measurably does NOT survive this — which is what makes it rung 4b's thesis
    // doing work rather than a property nothing depended on.
    "baleen: dmaflight OK",
    // ★★ ㉑ — the SMMU's TRANSLATION is per-stream, not merely its permission. Two live requesters
    // walking two different Stage-2 images: the same two addresses answered opposite ways by which
    // device asked. Rung 2 phase 3 already showed permission is per-stream (a permissive entry at a
    // neighbouring StreamID does not let the device through); this is the half that needed a second
    // requester, and it is the half the confinement story actually rests on.
    "baleen: twomasters OK",
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
    // Still forbidden, and now doing MORE work: the full-bank halt used to print through this very
    // prefix, so a regression that reinstates it reddens here as well as losing the marker above.
    "baleen: LINUX GUEST TRAP",
    "baleen: lroverflow FAIL",
    "baleen: tickdefer FAIL",
    // ★★ ⑱-4b-ii's negative half, and the load-bearing half of that rung's guest-observed witness.
    //
    // MEASURED as the EXACT baseline output: with `cpu@1` in the device tree and `CPU_ON` still
    // answering NOT_SUPPORTED, both kernels print `psci: failed to boot CPU1 (-95)` and then this
    // line, and the boot otherwise succeeds. So it is precisely the string a regression produces.
    //
    // It is forbidden in EVERY configuration, and that is deliberate: it fires for whichever guest
    // failed, which is the "both guests" coverage the required `SMP: Total of 2` substring cannot
    // give on its own. It also catches the case `baleen: vcpus OK` cannot see at all — a build where
    // CPU_ON silently never fires leaves `seeded == admitted` reading `0 == 0` and that marker green.
    "SMP: Total of 1 processors activated.",
    // ⑱-4b-i's negative half. It fires for three distinguishable reasons and the message says which:
    // a vCPU EL2 blocked that the model does not report as `Blocked`; a vCPU blocked and never woken
    // (a STARVED guest — what the kill probe induces); or no guest idling at all, which would mean
    // `guest-init.sh`'s sleep had stopped producing the state the witness is about.
    "baleen: idle FAIL",
    "Kernel panic",
    "baleen: linux model setup",
    "baleen: vpl011 FAIL",
    // ③-a2's negative halves. `vtimer FAIL` means EL2 never took a timer interrupt — with `IMO=1`
    // that is a guest running on a tick it should not have been able to receive. `vsgi FAIL` means
    // no `ICC_SGI1R_EL1` write ever trapped, i.e. the guest reached its own SGI generation register.
    "baleen: vtimer FAIL",
    "baleen: vsgi FAIL",
    // ⑱-6's negative half. `vspi FAIL` means the SPI the guest re-aimed did NOT reach a non-running
    // vCPU: either it went where the pCPU happened to be — `GICD_IROUTER` recorded and ignored, the
    // behaviour this rung removed — or the routing named no vCPU at all and it went nowhere.
    "baleen: vspi FAIL",
    // ⑱-7/⑱-8's negative half, and it fires for a reason worth distinguishing from a leak: not "an
    // interrupt crossed" but "**no interrupt target ever named a peer's affinity**", i.e. the HAZARD
    // the role fence exists for did not occur even once. That would mean the guests had stopped
    // colliding — `vcpu_affinity` gaining a guest argument would do it — and the whole argument for
    // why the fence is load-bearing would need re-reading.
    //
    // ⚠ ⑱-8 changed what the OK line counts: collisions, not refusals. A refusal counter would now
    // read zero and pass, because there is no longer a guard to fire.
    "baleen: irqconfine FAIL",
    // ⑲'s negative half, and it fires for two distinguishable reasons the message separates: a
    // banked RES0 copy that still RETIRES a conforming guest for a legal read, or a sweep that
    // collapsed (zero offsets checked, or nothing refused at all) and so proves nothing — the
    // vacuity trap the EL2-MMU page sweep needed for the same reason (design-lesson #214).
    "baleen: gicdsurface FAIL",
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
    // ③-b2b-ii-c2 follow-up: `HCR_EL2.TWI` did not take effect. Since ③-b2b-ii-e that costs
    // efficiency rather than the machine — an idle guest burns its whole slice instead of freezing
    // the pCPU — but a mechanism that silently stopped working is still a red.
    "baleen: wfi FAIL",
    // ③-b2b-ii-e: EL2's clock is not armed, not deliverable, not being completed, or not firing at
    // the rate its own deadline implies. The last of those is the one with teeth: EL2 runs
    // `EOImode=1`, so a missing `ICC_DIR_EL1` leaves EL2's OWN timer Active and the GIC never
    // signals it again — EL2 gets exactly one slice for the whole boot, and re-entry silently goes
    // back to depending on the guest.
    "baleen: slice FAIL",
    // ③-b2b-ii-f: a switch-in did not read back the FP register file it restored, so part of
    // `v0..v31`/`FPCR`/`FPSR` is being dropped and a guest resumes on its peer's floating-point
    // state. The only detector — the poison alone does not kill this boot.
    "baleen: fp FAIL",
    "baleen: vapr FAIL",
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
    // ⑲-3a: a guest wrote inside the range its own device tree reserves `no-map`, or the pad stopped
    // being mapped/writable at all. Either way the DMA landing pad is not the undisturbed page
    // ⑲-3b aims a live bus master at while both kernels are running.
    "baleen: dmapad FAIL",
    // ⑲-3b: the in-flight observation did not complete, or one of its arms did not behave. The
    // message names every counter, so the failing conjunct is readable without a rebuild.
    "baleen: dmaflight FAIL",
    // ㉑: the 2x2 did not come out, or releasing one device did not deny exactly one stream.
    "baleen: twomasters FAIL",
];

/// How long to let the boot run before declaring it hung. Generous on purpose: this is cross-arch
/// TCG on a CI runner, and the cost of a too-tight cap is an intermittently-red REQUIRED gate.
/// Overridable with `$BALEEN_LINUX_WAIT` (seconds) — the same escape hatch `boot-test.sh` gives.
const LINUX_WAIT_SECS_DEFAULT: u64 = 300;

/// Boot the real-Linux config headlessly and assert its markers. Returns whether every required
/// marker appeared and no forbidden one did; dumps the whole serial log on failure, since a boot
/// failure is diagnosed from the log or not at all.
fn boot_and_check_linux(argv: &[&str], boot: LinuxBoot) -> bool {
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
    // The fault-probe boot ends differently ON PURPOSE, so it gets its own corpus: dom 1 is retired
    // mid-boot and never issues `SYSTEM_OFF`, so half of `LINUX_MARKERS` would be legitimately
    // absent. `LINUX_FORBIDDEN` is SHARED and unweakened — `LINUX GUEST TRAP` now means "EL2 hit
    // something fatal", which must not happen in either run, and the guest-fault diagnostics were
    // renamed to `guest FAULT:` precisely so that canary keeps its meaning here.
    // ⑲-1: the SMMU boot's corpus is a CONCATENATION, built here rather than written out, so the
    // guest half stays literally `LINUX_MARKERS` and cannot drift from the shipped boot's.
    let markers: Vec<&str> = match boot {
        LinuxBoot::Shipped => LINUX_MARKERS.to_vec(),
        LinuxBoot::UnmappedFault => LINUX_FAULT_MARKERS.to_vec(),
        LinuxBoot::PeerLoop => LINUX_PEER_LOOP_MARKERS.to_vec(),
        LinuxBoot::Smmu => LINUX_MARKERS
            .iter()
            .chain(LINUX_SMMU_MARKERS.iter())
            .copied()
            .collect(),
    };
    for m in &markers {
        if serial.contains(m) {
            println!("qemu-linux-test: OK — found '{m}'");
        } else {
            println!("qemu-linux-test: FAIL — marker '{m}' not found");
            failed = true;
        }
    }
    // `LINUX_FAULT_FORBIDDEN` applies to BOTH retiring boots: in each of them a domain was KILLED,
    // so neither may claim every guest powered off, and dom 1 may not claim it shut down.
    let forbidden = LINUX_FORBIDDEN.iter().chain(match boot {
        LinuxBoot::Shipped | LinuxBoot::Smmu => [].iter(),
        LinuxBoot::UnmappedFault | LinuxBoot::PeerLoop => LINUX_FAULT_FORBIDDEN.iter(),
    });
    for m in forbidden {
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
    // ⑲-3b: keep the serial on a GREEN boot when asked. A passing gate prints only its marker
    // verdicts, so every measurement taken from a boot that works — which is most of them, since a
    // probe's whole point is to succeed and report a number — needed the log resurrecting by some
    // temporary edit. `BALEEN_KEEP_LOG=1 cargo xtask qemu-linux-smmu` leaves it in place and says
    // where. A failing boot still dumps it inline, unchanged.
    if std::env::var("BALEEN_KEEP_LOG").is_ok() {
        println!("qemu-linux-test: serial log kept at {}", out.display());
    } else {
        let _ = std::fs::remove_file(&out);
    }
    !failed
}

/// Build `hv-metal` for the bare-metal target with `real-linux` + `selftest` (M5 Arc 5e/6b).
fn metal_build_linux(boot: LinuxBoot) -> bool {
    // ⑲-1: the SMMU boot needs the `smmu` feature as well — the machine has an SMMU, so the binary
    // must be the one that programs it. Every other boot is unchanged.
    //
    // ⑳-f — **the two strings are consts shared with [`METAL_LINT_CONFIGS`], not literals typed
    // here.** They used to be typed in both places, which is the drift ⑭b found the hard way: the
    // lint list carried `real-linux` (which nothing ships) while this function built
    // `real-linux,selftest` (which the REQUIRED job boots), so the shipped binary was linted by
    // nothing. Sharing the declaration makes that unspellable rather than checked — the same move
    // ⑳-e made for memory types, and the reason the linux half of ⑳-f's invariant needs no parser.
    let features = match boot {
        LinuxBoot::Smmu => LINUX_SMMU_FEATURES,
        _ => LINUX_FEATURES,
    };
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
            features,
        ],
    )
}

/// The feature set every real-Linux boot builds — `qemu-linux`, and the REQUIRED
/// `real-linux boot (QEMU)` gate. Declared once and used by **both** [`metal_build_linux`] and
/// [`METAL_LINT_CONFIGS`], so the config that ships and the config that is linted are the same
/// token rather than two strings that agree today (⑳-f).
const LINUX_FEATURES: &str = "real-linux,selftest";
/// As [`LINUX_FEATURES`], for the SMMU boot (⑲-1) — the machine has an SMMU, so the binary must be
/// the one that programs it.
const LINUX_SMMU_FEATURES: &str = "real-linux,selftest,smmu";

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
///   the SIX `boot_and_check` invocations in `hv-metal/boot-test.sh` — default · selftest ·
///     dma-control (default features) · smmu · **wx-probe** · **xn-probe**
///   [`LINUX_FEATURES`] / [`LINUX_SMMU_FEATURES`] -> `metal_build_linux` below
/// `real-linux` alone is kept too: it is seconds, and it covers the non-selftest path.
///
/// ⚠ **⑳-f — THAT LIST USED TO READ "default · selftest · smmu", AND THE UNDERCOUNT WAS THE BUG.**
/// Naming three of the six sources made the two it omitted invisible: `wx-probe` and `xn-probe`
/// were booted by a required gate and linted by nothing. **A pointer to where the truth lives is
/// only as good as its own completeness** — which is why the shell half is now READ rather than
/// summarised, by [`check_lint_configs_cover_booted`]. The linux half needs no reading: it is the
/// same two consts this list and `metal_build_linux` both use.
const METAL_LINT_CONFIGS: &[&[&str]] = &[
    &[],
    &["--features", "selftest"],
    &["--features", "smmu"],
    &["--features", "real-linux"],
    &["--features", LINUX_FEATURES],
    // ⑳-f — **the two configs a REQUIRED gate boots and nothing linted.** `boot-test.sh` runs six
    // `boot_and_check` invocations; this list carried four of their feature sets. `wx-probe` and
    // `xn-probe` are built and booted by `metal boot (QEMU)` on every PR, and their code — the W^X
    // and execute-never witnesses, which are the whole evidence for EL2 protecting its own memory —
    // was covered by no clippy and no rustdoc, ever.
    //
    // ⚠ **The list already contained the WEAKER version of this case.** `spi-route-probe` and
    // `no-irq-confinement` are here precisely because nothing boots them (see below, citing #212).
    // The two configs a gate *does* boot were the ones missing. **Measured at the time of the fix:
    // both are clean** — this closes a hole rather than fixing a defect, and the only reason anyone
    // knew they were clean was a by-hand run, which is what "ungated" means.
    &["--features", "wx-probe"],
    &["--features", "xn-probe"],
    // ⑲-1 — the combined configuration. It is BUILT AND BOOTED by `qemu-linux-test`'s `Smmu` boot,
    // so by this list's own stated invariant it must be linted; before this rung it was a config
    // that compiled and that no gate ever looked at, which is ⑭b's finding one rung along.
    &["--features", LINUX_SMMU_FEATURES],
    // ⑱-6 — the removed-fix probe. It is NOT booted by any gate (it is run by hand and its result is
    // tabulated in `docs/VGIC-SPI-ROUTING.md`), so this is the list's invariant read the other way:
    // a probe nothing lints is a probe that can stop compiling without anyone finding out until the
    // day it is needed, which is the day its evidence is least replaceable. ⚠ Design-lesson #212 —
    // a fix, or a probe, that is never wired into anything is indistinguishable from its absence.
    &["--features", "real-linux,selftest,spi-route-probe"],
    // ⑱-7's removed-fix probe, linted for the same reason as ⑱-6's above.
    &["--features", "real-linux,selftest,no-irq-confinement"],
];

/// The measurement instrument, and — like `hv-metal` — a crate **no `--workspace` gate reaches**.
const FVP_DIR: &str = "fvp-probe";

/// The board-bring-up instrument (⑯-hw phase 0): measures the platform facts `hv-metal` assumes
/// from QEMU `virt`, so a port is scoped from numbers rather than from guesses. Same exclusion and
/// the same reason as [`FVP_DIR`].
const BOARD_PROBE_DIR: &str = "board-probe";

/// **Lint and build `fvp-probe`: `fmt --check` + `clippy -D warnings` + `build` + `doc -D warnings`.**
///
/// ## Why this exists, and it is the same hole [`metal_lint`] was dug for
///
/// `fvp-probe` is workspace-EXCLUDED, so until this task **nothing in CI built it at all** — zero
/// references in `.github/workflows/`, zero in this file. Design-lesson #173's shape again:
/// excluding a crate to escape one gate silently excuses it from all of them. `hv-metal` got
/// [`metal_lint`] for exactly this reason; the probe simply never did, back when it was small.
///
/// ⚠ **What made it urgent is not the line count — it is what the crate now carries.**
///
/// * `layout.rs`'s `ASSERT_DISJOINT` is a **compile-time** check that two physical regions never
///   overlap. It was written *because* three of them silently did. A `const` assertion fires only
///   when something **compiles the crate** — so until this task it was a gate nobody ran, and the
///   exact overlap it exists to prevent could have been reintroduced with every CI check green.
///   That is design-lesson #199 (a gate you merely OBSERVE is not a gate) landing on the file
///   written to prevent that class of defect.
/// * Milestones 3–6 are the **only evidence** for what ledger 5's A2 must do — m6 is what
///   establishes that `smmu::publish`'s barrier is insufficient once EL2's mappings are cacheable.
///   An instrument that silently stops compiling is an argument that silently stops existing.
///
/// ## What this does NOT do, stated so the gate is not read for more than it is
///
/// **It does not run the model.** The AEM is an 885 MB download driven inside a Linux VM; CI builds
/// the probe and checks its health, and the milestone **verdicts remain local evidence**, exactly as
/// they were. What becomes gated is that the code compiles, lints, formats, documents — and that its
/// compile-time assertions are actually evaluated.
/// Every standalone instrument crate this task keeps healthy.
///
/// ⚠ **`board-probe` was added here in the SAME commit that created it, and that ordering is the
/// point.** `fvp-probe` existed for four milestones before anything built it — #176's finding was
/// literally "the instrument A2 will rest on was built by nothing at all". Adding a second probe
/// without adding it here would have reproduced that exactly, one crate along, which is
/// design-lesson **#262**: extending a rule to a new case is the moment to re-derive it, because
/// the person adding the case is the last one who will re-check the rule's base.
const PROBE_DIRS: &[&str] = &[FVP_DIR, BOARD_PROBE_DIR];

/// Lint every crate in [`PROBE_DIRS`] — fmt, clippy `-D warnings`, build, and rustdoc
/// `-D warnings`.
///
/// ⚠ These crates are **workspace-excluded**, so `cargo xtask ci`'s workspace-scoped gates never
/// touch them (design-lesson #173: excluding a crate to escape one gate silently excuses it from
/// all of them). This task is the only thing holding them to any bar.
///
/// ★ It checks their **health**, never their **results**. A probe's verdicts come from hardware or
/// a model CI does not have, so they are LOCAL evidence — what this can guarantee is that the
/// instrument still compiles, which is the thing that rots silently between uses.
fn fvp_lint() -> bool {
    PROBE_DIRS.iter().all(|dir| {
        run_in(dir, "cargo", &["fmt", "--", "--check"])
            && run_in(
                dir,
                "cargo",
                &["clippy", "--release", "--", "-D", "warnings"],
            )
            && run_in(dir, "cargo", &["build", "--release"])
            && run_in_env(
                dir,
                "cargo",
                &["doc", "--no-deps"],
                &[("RUSTDOCFLAGS", "-D warnings")],
            )
    })
}

/// How many `boot_and_check` invocations [`BOOT_TEST`] is expected to contain.
///
/// ⚠⚠ **This pin exists because a parser that matches NOTHING would otherwise pass vacuously**, and
/// that is the failure mode of every checker this project has got wrong (design-lesson #215 — ask
/// what a checker prints when there is nothing to check). If `boot-test.sh` is restructured, the
/// helper renamed, or the quoting convention changed, [`booted_feature_sets`] finds zero configs,
/// every one of them is trivially "covered", and the gate reports OK on no evidence. Pinning the
/// count makes that case RED.
///
/// ⚠ Raising it is normal — a new boot is a new config. **Lowering it is a claim that a boot should
/// no longer exist**, and belongs in the commit message.
const BOOT_TEST_CONFIGS: usize = 6;

/// Every feature set [`BOOT_TEST`] actually builds and boots, parsed out of the script.
///
/// ## The convention this relies on, stated rather than left to be inferred
///
/// Each boot is one line of the form `boot_and_check "<label>" "<feature args>" \`, where the
/// feature field is either empty or `--features <list>`. That is the shape all six invocations have
/// and the shape [`booted_feature_sets`] reads; a boot written any other way is not found, which is
/// what [`BOOT_TEST_CONFIGS`] is there to catch.
///
/// **No regex, deliberately.** Six of this project's own checkers have been broken by clever
/// matching — a `\bldxr` that could not match `ldaxr`, a pattern that broke on Rust's `\`-newline
/// continuation, a literal matcher blind to `{}` placeholders. Plain `split` on quotes is duller
/// and cannot be subtly wrong.
///
/// Returns the feature ARGUMENT VECTORS, in [`METAL_LINT_CONFIGS`]'s own shape, so the comparison
/// below is between two things of the same type rather than between a string and a parse of it.
fn booted_feature_sets(script: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for line in script.lines() {
        let Some(rest) = line.strip_prefix("boot_and_check ") else {
            continue;
        };
        // `"<label>" "<features>" \` — take the SECOND quoted field.
        let mut fields = rest.split('"').skip(1).step_by(2);
        let (Some(_label), Some(features)) = (fields.next(), fields.next()) else {
            continue;
        };
        out.push(
            features
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>(),
        );
    }
    out
}

/// ★★ ⑳-f — **THE FIFTH EVIDENCE CORPUS, PINNED: the lint-config set.**
///
/// ⑳/⑳-b/⑳-c/⑳-d pinned the Kani harnesses, the Verus obligations, the deep sweeps and the boot
/// markers. [`METAL_LINT_CONFIGS`] is the fifth body of evidence and was the only one with no
/// universe check — over `hv-metal`, the one crate carrying `unsafe`, workspace-EXCLUDED, where this
/// task is the **sole** thing holding it to `-D warnings`.
///
/// ⚠ **The list stated this invariant itself, twice, and did not hold it**: *"every feature config
/// that has code of its own is here, or that config's code is linted by nobody"*, and *"every
/// configuration that is BUILT AND BOOTED is linted"*. It named `boot-test.sh`'s `boot_and_check`
/// invocations as where the shipped set is defined — and then listed three of the six. `wx-probe`
/// and `xn-probe` were booted by the REQUIRED `metal boot (QEMU)` job and linted by nothing.
///
/// ★ **A prose invariant is a claim nothing checks (design-lesson #230); this is the same sentence
/// as code.** It is deliberately a SUBSET test rather than an equality: [`METAL_LINT_CONFIGS`]
/// legitimately holds configs no gate boots (`real-linux` alone; the two removed-fix probes, kept
/// per #212), and demanding equality would force those out — losing coverage to satisfy a checker,
/// which is the wrong direction.
fn check_lint_configs_cover_booted() -> bool {
    let script = match std::fs::read_to_string(BOOT_TEST) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("metal-lint: cannot read {BOOT_TEST}: {e}");
            return false;
        }
    };
    let booted = booted_feature_sets(&script);
    if booted.len() != BOOT_TEST_CONFIGS {
        eprintln!(
            "metal-lint: FAIL — {BOOT_TEST} yielded {} boot config(s), expected \
             {BOOT_TEST_CONFIGS}. Either a boot was added/removed (update BOOT_TEST_CONFIGS) or \
             the `boot_and_check \"<label>\" \"<features>\"` convention changed and this check is \
             now reading nothing.",
            booted.len()
        );
        return false;
    }
    let linted: Vec<Vec<String>> = METAL_LINT_CONFIGS
        .iter()
        .map(|c| c.iter().map(|s| s.to_string()).collect())
        .collect();
    let mut ok = true;
    for cfg in &booted {
        if !linted.contains(cfg) {
            let shown = if cfg.is_empty() {
                "(default, no features)".to_string()
            } else {
                cfg.join(" ")
            };
            eprintln!(
                "metal-lint: FAIL — {BOOT_TEST} boots `{shown}` and METAL_LINT_CONFIGS does not \
                 cover it. A booted configuration linted by nobody is exactly what this list's own \
                 invariant forbids."
            );
            ok = false;
        }
    }
    if ok {
        eprintln!(
            "metal-lint: OK — all {BOOT_TEST_CONFIGS} booted configs are covered by {} lint configs",
            METAL_LINT_CONFIGS.len()
        );
    }
    ok
}

/// Lint `hv-metal` — fmt `--check`, then clippy `-D warnings` and rustdoc `-D warnings` on the
/// bare-metal target for **every config in [`METAL_LINT_CONFIGS`]**. `hv-metal` is excluded from the
/// workspace, so `cargo xtask ci`'s workspace-scoped fmt/clippy never touch it — yet it is the ONE
/// crate that carries `unsafe`, so it must stay under the same `-D warnings` bar. The
/// `metal boot (QEMU)` CI job runs this, so the gate is enforced (single source of truth: CI calls
/// this task).
///
/// ⚠ **⑳-f — THIS DOC WAS ATTACHED TO [`METAL_LINT_CONFIGS`], NOT TO THIS FUNCTION, AND SAID "for
/// BOTH feature configs (default and `selftest`)".** It described the task while sitting on the
/// list, and by then the list held eight. Two separate small failures with one cause: text that
/// documents a *behaviour* parked on a *constant* stops being read as a claim about the behaviour,
/// so nobody updated it as the list grew from two entries to eight. Moved to the thing it describes,
/// and it now names the list instead of counting it (the count is derived for the usage text, and
/// prose that restates a number is a number that drifts).
///
/// Note: no `--all-targets` — a `#![no_std] #![no_main]` bare-metal bin has no buildable `test`
/// target (the test harness needs `std`), so `--all-targets` would fail to compile it.
fn metal_lint() -> bool {
    // The universe check runs FIRST, and before any cargo invocation: it is cheap, and a lint set
    // that does not cover what ships is a fact worth learning before spending a minute proving the
    // subset it does cover is clean.
    check_lint_configs_cover_booted()
        && run(
            "cargo",
            &[
                "fmt",
                "--manifest-path",
                "hv-metal/Cargo.toml",
                "--",
                "--check",
            ],
        )
        && METAL_LINT_CONFIGS.iter().all(|cfg| metal_clippy(cfg))
        && METAL_LINT_CONFIGS.iter().all(|cfg| metal_doc(cfg))
}

/// **Build `hv-metal`'s rustdoc for one feature config, denying every rustdoc warning.**
///
/// ## Why this exists: an EXCLUDED crate loses every `--workspace` gate, not just the one
///
/// `cargo xtask doc` runs `cargo doc --workspace`, and `hv-metal` is workspace-**excluded** — so
/// until this rung its rustdoc was built by **nothing at all**, in any job, ever. `metal-lint`
/// covered `fmt` and `clippy` for it and stopped there. Design-lesson #173 is the general form:
/// excluding a crate to escape one gate silently excuses it from all of them.
///
/// **MEASURED when the gate was added: 33 distinct broken intra-doc links**, across every module and
/// every feature config — 24 in the default build, 23 under `selftest`, **30 under `smmu`**, 18
/// under `real-linux`, 17 under `real-linux,selftest`. Given how much of this project's argument
/// lives in doc comments, links that rot silently are a real cost.
///
/// ⚠ **PER CONFIG, and that is load-bearing rather than thorough-for-its-own-sake.** The count above
/// is not uniform: `smmu` was the worst and `real-linux` — the only config anyone had ever measured
/// — was among the best. A single-config gate would have reported 18, "fixed" those, and left 15
/// live in configurations it never built. That is design-lesson #155's shape (an audit that measures
/// one case and generalises), and it is why this iterates [`METAL_LINT_CONFIGS`] exactly as clippy
/// does: the invariant that list already states is *every configuration that is BUILT AND BOOTED is
/// linted*, and "linted" now includes its docs.
///
/// `-D warnings` rather than `-D rustdoc::broken_intra_doc_links`, matching [`doc`]'s bar for the
/// workspace: all five configs meet it today, so the stricter form costs nothing and catches the
/// next class too.
fn metal_doc(extra: &[&str]) -> bool {
    let mut args = vec![
        "doc",
        "--manifest-path",
        "hv-metal/Cargo.toml",
        "--target",
        METAL_TARGET,
        "--no-deps",
    ];
    args.extend_from_slice(extra);
    run_env("cargo", &args, &[("RUSTDOCFLAGS", "-D warnings")])
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

/// This file, read back at run time so [`doc_markers`] can enumerate the marker arrays that exist
/// rather than only the ones its own table already lists. `xtask` runs from the repo root — the
/// same assumption [`BOOT_TEST`] has always made.
const SELF_SRC: &str = "xtask/src/main.rs";

/// ★★ ⑳-d — **THE FOURTH EVIDENCE CORPUS, PINNED: the boot markers.**
///
/// ⚠ **The gate this closes is the one ⑳/⑳-b/⑳-c closed for the other three, left open here.**
/// [`doc_markers`] computes the marker corpus and prints its size **as information**. Nothing
/// asserted it. So deleting a marker from any array below left `doc-markers` printing one fewer and
/// returning OK, and left the boot gate simply checking one fewer thing — **green, both of them**.
/// The only accidental cover was that a marker *quoted in a doc* is caught by the drift check
/// below, and that pins at most 46 of ~214.
///
/// ★ **Why this corpus deserves the same treatment as the three proof corpora, not less.**
/// `hv-metal` is workspace-EXCLUDED and cannot be a Kani target (honest-ledger item 8). These
/// markers are therefore not *one* source of evidence for the metal — they are the **only** one.
///
/// ⚠ **Pinned by COUNT, not by name, and that is deliberate.** `KANI_HARNESSES` lists names because
/// a harness name is short and a rename should be visible. A marker is a whole sentence; listing
/// all ~214 here would be a second copy of the corpus, which is design-lesson #230's defect — and
/// #240's, in the very file that would then have to keep both copies in step.
///
/// ⚠ **Counts are PRE-dedup and PER ARRAY** — finer than one grand total on purpose, so a deletion
/// in one array cannot be masked by an addition in another. The deduped total stays in the OK line
/// as information, where it always was.
///
/// ⚠ **Raising a number here is a normal part of adding a witness; LOWERING one is a claim that a
/// witness should no longer exist, and belongs in the commit message.**
const MARKER_CORPUS: &[(&str, &[&str], usize)] = &[
    ("LINUX_MARKERS", LINUX_MARKERS, 66),
    ("LINUX_FORBIDDEN", LINUX_FORBIDDEN, 27),
    ("LINUX_FAULT_MARKERS", LINUX_FAULT_MARKERS, 5),
    ("LINUX_PEER_LOOP_MARKERS", LINUX_PEER_LOOP_MARKERS, 5),
    ("LINUX_FAULT_FORBIDDEN", LINUX_FAULT_FORBIDDEN, 2),
    // ⚠ **FOUND BY THIS GATE'S OWN UNIVERSE CHECK, on its first run (⑳-d).** These 8 are asserted
    // by the `LinuxBoot::Smmu` boot, but the census below chained five arrays and not this one —
    // so an SMMU marker quoted in a doc was outside the drift check, under a comment claiming the
    // census covered everything. Latent, not live: no doc quotes one today (checked). Listing it
    // here pins it AND puts it in the census, because both now read this one table.
    ("LINUX_SMMU_MARKERS", LINUX_SMMU_MARKERS, 8),
];

/// The number of marker lines [`BOOT_TEST`] contributes — the synthetic path's half of the corpus.
///
/// Pinned separately from [`MARKER_CORPUS`] because it is derived from a FILE rather than a
/// compile-time array: `boot-test.sh` is where the `default`/`selftest`/`dma-control`/`smmu`/
/// `wx-probe`/`xn-probe` boots name what they expect, and a marker deleted there is exactly as
/// silent as one deleted from an array.
/// ★ **177 since ledger 5's A2 (+1).** The `default` boot now asserts
/// `"EL2 MMU on, data cacheable (C=1)"`, which no guest-running boot asserted before: the EL2-MMU
/// marker existed only in the terminal `wx-probe`/`xn-probe` configurations. Raising a number here
/// is the normal shape of adding a witness — see the block comment on [`MARKER_CORPUS`] for why
/// LOWERING one is a different kind of claim.
const BOOT_TEST_MARKERS: usize = 177;

/// Every marker array [`MARKER_CORPUS`] must account for, found by reading this file.
///
/// ⚠ **Without this, the pin is one-directional.** The table above catches a marker deleted from an
/// array it already lists; it is blind to a NEW array added and never listed, which would be
/// ungated from birth and look exactly like a corpus that was never supposed to cover it. That is
/// the same hole `verus_counts` closes by listing the directory rather than trusting its own table
/// — the difference being that the universe here is a source file, not a directory.
///
/// ★ **It earned its cost immediately**: on its first run it found `LINUX_SMMU_MARKERS`, which the
/// census had omitted since the SMMU boot was added (design-lesson #211 — build the control so it
/// can falsify itself).
///
/// The convention this relies on, and it is the existing one: a marker array is a `const LINUX_*`
/// of type `&[&str]`. A new corpus that follows it is caught; one that does not is not, which is
/// why the naming is stated here rather than left to be inferred.
fn declared_marker_arrays(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in src.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix("const LINUX_") else {
            continue;
        };
        let Some((name, ty)) = rest.split_once(':') else {
            continue;
        };
        if ty.trim_start().starts_with("&[&str]") {
            out.push(format!("LINUX_{name}"));
        }
    }
    out
}

/// Assert that every boot marker a doc QUOTES is still a marker the gates check, and — since ⑳-d —
/// that the corpus still holds the number of markers [`MARKER_CORPUS`] pins. See the block comment
/// above for the drift rule and its limits.
fn doc_markers() -> bool {
    eprintln!("$ xtask doc-markers");

    // The gate corpus.
    // EVERY marker array, including the fault-probe run's and the SMMU boot's. A marker outside
    // this census is outside the drift check that is this task's whole purpose: a doc could quote
    // it, `hv-metal` could reword it, and nothing would notice.
    //
    // ⚠ **This comment used to say "ALL FOUR corpora" while the chain below listed FIVE arrays and
    // omitted a sixth (`LINUX_SMMU_MARKERS`).** Two different miscounts in the one place whose job
    // is to be exhaustive — which is why the census is now derived from `MARKER_CORPUS`, and that
    // table is checked against the arrays this file actually declares. A prose count of a corpus is
    // design-lesson #230's defect wearing #227's clothes: it reads as an inventory.
    let mut gate: Vec<String> = MARKER_CORPUS
        .iter()
        .flat_map(|(_, markers, _)| markers.iter())
        .map(|m| collapse(m))
        .collect();
    let script = match std::fs::read_to_string(BOOT_TEST) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("doc-markers: cannot read {BOOT_TEST}: {e}");
            return false;
        }
    };
    let mut from_script = 0usize;
    for line in script.lines() {
        if let Some(s) = shell_string(line) {
            gate.push(collapse(&s));
            from_script += 1;
        }
    }

    // ★★ ⑳-d — THE CARDINALITY PIN. Checked BEFORE the drift check, because a corpus that has
    // silently lost a member makes every downstream "still exact" verdict a statement about a
    // smaller set than the one the reader thinks was checked.
    let mut census_ok = true;
    for (name, markers, want) in MARKER_CORPUS {
        if markers.len() != *want {
            eprintln!(
                "doc-markers: FAIL — {name} holds {} marker(s), expected {want}. {}",
                markers.len(),
                if markers.len() < *want {
                    "A witness was REMOVED: say why in the commit message, then lower the pin."
                } else {
                    "A witness was ADDED: raise the pin in `MARKER_CORPUS`."
                }
            );
            census_ok = false;
        }
    }
    if from_script != BOOT_TEST_MARKERS {
        eprintln!(
            "doc-markers: FAIL — {BOOT_TEST} contributes {from_script} marker(s), expected \
             {BOOT_TEST_MARKERS}. Update `BOOT_TEST_MARKERS` if the change is intended."
        );
        census_ok = false;
    }
    // The other direction: a NEW marker array that nothing pins. Without this the table only guards
    // the arrays it already knows about (design-lesson #231 — pin the cardinality in BOTH
    // directions, or the half you skipped is the half that bites).
    match std::fs::read_to_string(SELF_SRC) {
        Ok(src) => {
            for name in declared_marker_arrays(&src) {
                if !MARKER_CORPUS.iter().any(|(n, _, _)| *n == name) {
                    eprintln!(
                        "doc-markers: FAIL — `{name}` is a marker array that `MARKER_CORPUS` does \
                         not pin, so it is ungated. Add it with its count."
                    );
                    census_ok = false;
                }
            }
        }
        Err(e) => {
            eprintln!("doc-markers: cannot read {SELF_SRC}: {e}");
            return false;
        }
    }
    if !census_ok {
        return false;
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

/// **Run a command, ECHOING its output line by line while also returning it.**
///
/// ⚠ **Exists because a gate that captures where the command it replaced STREAMED is worse on two
/// axes at once**, and both were nearly shipped: a proof failure's diagnostics vanish unless
/// reprinted, and a 16-minute step goes silent, which reads as hung. Streaming keeps the behaviour
/// `cargo kani …` and `verus …` had when CI invoked them directly; the returned copy is what the
/// inventory checks parse.
///
/// Merges stderr into stdout so the ordering a reader sees matches the ordering the tool produced.
fn run_capturing(program: &str, args: &[&str]) -> Option<(bool, String)> {
    eprintln!("$ {program} {}", args.join(" "));
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    // ⚠ **stderr is drained on its OWN THREAD, and that is not tidiness — it is the difference
    // between this working and hanging a REQUIRED gate.** Reading stdout to completion first and
    // stderr afterwards deadlocks the moment a child writes more to stderr than the pipe buffer
    // holds (~64 KiB): the child blocks writing stderr, this blocks reading stdout, and neither
    // moves. `cargo` puts every `Compiling …` line and every warning on stderr, so the volume is
    // not hypothetical — it is merely small enough today.
    let err = child.stderr.take().map(|e| {
        std::thread::spawn(move || {
            let mut acc = String::new();
            for line in BufReader::new(e).lines().map_while(Result::ok) {
                eprintln!("{line}");
                acc.push_str(&line);
                acc.push('\n');
            }
            acc
        })
    });

    let mut text = String::new();
    if let Some(o) = child.stdout.take() {
        for line in BufReader::new(o).lines().map_while(Result::ok) {
            eprintln!("{line}");
            text.push_str(&line);
            text.push('\n');
        }
    }
    if let Some(h) = err {
        if let Ok(acc) = h.join() {
            text.push_str(&acc);
        }
    }
    let status = child.wait().ok()?;
    Some((status.success(), text))
}

/// ★★ ⑳-c — **EVERY DEEP EXHAUSTIVE SWEEP, by test name.** The third and last corpus this project's
/// evidence rests on, after `VERUS_OBLIGATIONS` (⑳) and `KANI_HARNESSES` (⑳-b).
///
/// ⚠ **`cargo test -- --ignored` exits 0 whether it runs 23 sweeps or 22.** These are the Tier A/B
/// enumerator evidence — `local_respect_holds_deep`, the `step_consistency_holds_*` family,
/// `write_xor_execute_saturates`, `domain_id_reuse_deep` — and they run **only in the weekly
/// `deep-verify` job**, so a deleted one would go unnoticed for a week at best.
///
/// ★ **Worse than the other two corpora, and the reason is the `#[ignore]` pairing.** Each deep
/// sweep has a CI-shallow twin (`enumerate.rs`: *"Each has a CI-shallow test … and a deep
/// `#[ignore]`d twin"*). Delete the twin and the shallow one still passes in `cargo test`, so the
/// ordinary gate stays green while the exhaustive evidence quietly halves. Removing `#[ignore]` from
/// one is just as silent in the other direction: it then runs in `ci` (slowly) and **not** in the
/// `--ignored` sweep at all.
///
/// ★ **Checked in `cargo xtask ci`, not only in the proof jobs** — `--list` enumerates without
/// running, measured at **~2 s** on a warm cache, so unlike ⑳/⑳-b this inventory is verified on
/// EVERY PR rather than only on proof-path ones.
const DEEP_SWEEPS: &[&str] = &[
    "enumerate::tests::all_affinity_deep",
    "enumerate::tests::delegation_crossed_with_grant_and_evtchn_deep",
    "enumerate::tests::delegation_forest_deep",
    "enumerate::tests::device_assignment_saturates",
    "enumerate::tests::domain_id_reuse_deep",
    "enumerate::tests::domain_lifecycle_deep",
    "enumerate::tests::evtchn_and_sched_seam_deep",
    "enumerate::tests::grant_and_p2m_seams_deep",
    "enumerate::tests::grant_p2m_over_three_domains_deep",
    "enumerate::tests::hierarchy_saturates_only_under_symmetry_reduction",
    "enumerate::tests::integrated_core_deep",
    "enumerate::tests::symmetry_group_closes_saturated_set_frame_grant",
    "enumerate::tests::the_four_level_hierarchy_deep",
    "enumerate::tests::vcpu_affinity_deep",
    "enumerate::tests::write_xor_execute_saturates",
    "noninterference::tests::an_unmediated_allocator_breaks_step_consistency",
    "noninterference::tests::local_respect_holds_deep",
    "noninterference::tests::local_respect_holds_three_domains",
    "noninterference::tests::step_consistency_holds_over_the_delegation_forest_deep",
    "noninterference::tests::step_consistency_holds_over_the_page_table_guards_deep",
    "noninterference::tests::step_consistency_holds_per_domain_handles_with_destroy",
    "noninterference::tests::step_consistency_holds_three_domains_deep",
    "noninterference::tests::step_consistency_holds_with_a_mediated_allocator_deep",
];

/// **Check the deep-sweep corpus is exactly [`DEEP_SWEEPS`], without running it.**
///
/// `--ignored --list` enumerates the ignored tests and exits; the sweeps themselves peak at several
/// GB each and are `deep-verify`'s job. Both directions, for the reason `verus_counts` gives: a loop
/// over the table alone would not notice a sweep that exists and is unnamed.
fn deep_sweeps() -> bool {
    let Some((success, text)) = run_capturing(
        "cargo",
        &["test", "-p", "hv-sim", "--", "--ignored", "--list"],
    ) else {
        eprintln!("sweeps: cannot run cargo test");
        return false;
    };
    if !success {
        eprintln!("sweeps: FAIL — cargo test --list exited non-zero (output above).");
        return false;
    }
    let mut seen: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_suffix(": test"))
        .map(str::trim)
        .collect();
    seen.sort_unstable();
    seen.dedup();

    let mut ok = true;
    for want in DEEP_SWEEPS {
        if !seen.contains(want) {
            eprintln!("sweeps: FAIL — expected deep sweep is gone: {want}");
            ok = false;
        }
    }
    for got in &seen {
        if !DEEP_SWEEPS.contains(got) {
            eprintln!(
                "sweeps: FAIL — deep sweep exists but is not in DEEP_SWEEPS: {got}. Add it, so the \
                 list cannot fall behind the corpus."
            );
            ok = false;
        }
    }
    if ok {
        eprintln!(
            "sweeps: OK — {} deep exhaustive sweeps, all named",
            seen.len()
        );
    }
    ok
}

/// ★★ ㉓ — **run the fail-safe suite for the checker that decides whether the PROOF gate runs.**
///
/// `.github/scripts/detect-proof-changes.sh` writes the `run=` output that gates `kani proofs (PR)`
/// and `verus proofs (PR)` — two REQUIRED contexts standing in front of 136 harnesses and 117
/// obligations. **A false `run=false` lets a proof-breaking PR merge green**, which is exactly what
/// ① (#76) made those gates required to prevent.
///
/// ⚠ **It runs from `ci`, NOT from `proofs.yml`, and that placement is the whole point.** A test
/// that only ran when proof paths changed could not catch the defect where the decision *"proof
/// paths did not change"* is itself wrong — the failing case would skip its own test. Here it is
/// inside `fmt · clippy · test`, which is required on every PR.
///
/// Shelling out rather than reimplementing: the script is what CI executes, so testing anything
/// else would be testing a copy (the same reason `qemu-test` runs `boot-test.sh` rather than
/// re-encoding the boot).
fn proof_gate_test() -> bool {
    run("bash", &[".github/scripts/detect-proof-changes-test.sh"])
}

/// ★★ ⑳-b — **EVERY KANI HARNESS THIS CORPUS IS EXPECTED TO CONTAIN, by qualified name.**
///
/// ⚠ **Same hole ⑳ found in the Verus gate, in the LARGER corpus.** The required `kani proofs (PR)`
/// job runs `cargo kani -p hv-verify -j 4 --output-format=terse` and checks **exit status only** —
/// which is blind to a harness being DELETED. 135 harnesses passing is `0 failures` just as 136 is.
///
/// A **count** would catch a deletion; a **name set** also catches a rename, a harness moved out of
/// `#[cfg(kani)]`, and a delete-one-add-one refactor. Kani's terse output prints
/// `Checking harness <module>::<name>...` for every harness it runs, so the stronger check costs
/// nothing over the weaker one — which is why this is a list where `VERUS_OBLIGATIONS` is a count
/// (verus reports no per-obligation names to pin).
///
/// ⚠ **Adding a harness means adding a line here, deliberately — that is the feature**, and the same
/// bargain `LINUX_MARKERS` makes. **Removing one is a claim that a property no longer needs
/// proving, and belongs in the commit message.**
const KANI_HARNESSES: &[&str] = &[
    "device_assignment::an_assignment_moves_exactly_one_device",
    "device_assignment::assign_is_total_and_a_refusal_changes_nothing",
    "device_assignment::destroying_a_domain_leaves_no_device_naming_it",
    "device_assignment::no_domain_can_assign_itself_a_device",
    "device_assignment::release_is_total_and_only_moves_the_named_holders_device",
    "device_assignment::the_sweep_takes_exactly_the_holders_devices",
    "device_models::a_broadcast_names_every_vcpu_but_the_sender",
    "device_models::a_failed_write_changes_nothing",
    "device_models::a_foreign_cluster_names_no_vcpu",
    "device_models::a_foreign_cluster_route_names_no_vcpu",
    "device_models::a_guest_can_name_a_vcpu_that_is_not_itself",
    "device_models::a_guest_can_route_an_spi_to_a_second_vcpu",
    "device_models::a_layout_valid_for_two_has_room_for_two",
    "device_models::a_route_names_at_most_one_vcpu",
    "device_models::a_target_list_names_exactly_the_bits_it_sets",
    "device_models::a_valid_layout_decodes_within_the_frame_it_names",
    "device_models::a_write_changes_only_the_enables_it_names",
    "device_models::a_write_to_one_redistributor_changes_nothing_another_reads",
    "device_models::an_address_past_the_last_redistributor_is_in_no_frame",
    "device_models::an_any_of_n_route_names_no_vcpu",
    "device_models::an_sgi_intid_is_always_in_the_sgi_range",
    "device_models::enabling_an_intid_for_one_vcpu_does_not_enable_it_for_another",
    "device_models::gic_mmio_is_total_for_every_guest_offset",
    "device_models::gic_mmio_is_total_for_every_layout",
    "device_models::gic_mmio_is_total_with_two_redistributors",
    "device_models::only_an_spi_has_a_route",
    "device_models::only_the_writable_registers_can_change_the_pl011",
    "device_models::pl011_mmio_is_total_for_every_guest_offset",
    "device_models::pl011_reports_a_transmit_byte_only_for_dr",
    "device_models::the_decode_is_a_partition_across_redistributors",
    "device_models::the_decode_is_reached_and_does_something",
    "device_models::the_distributor_cannot_reach_a_redistributor_banked_intid",
    "device_models::the_distributor_declares_one_of_n_unsupported",
    "device_models::the_distributor_frame_cannot_change_anything_the_sgi_frame_reads",
    "device_models::the_last_redistributor_is_the_only_one_that_says_so",
    "device_models::the_needle_matcher_fires",
    "device_models::the_needle_matcher_never_runs_off_its_needle",
    "device_models::the_second_redistributor_is_reached_and_is_its_own",
    "device_models::the_sgi_frame_cannot_reach_an_spi",
    "device_models::the_typer_reports_the_vcpu_affinity",
    "device_models::two_redistributors_are_total_for_every_layout",
    "device_path_composition::a_device_never_reaches_an_unauthorized_frame",
    "device_path_composition::a_device_reaches_exactly_the_memory_its_domain_reaches",
    "device_path_composition::binding_the_wrong_domain_reaches_the_wrong_memory",
    "device_path_composition::the_composition_is_not_vacuous",
    "device_path_composition::the_two_consumers_are_pointed_at_one_table",
    "device_path_composition::the_walk_lands_where_the_windows_say",
    "foreign_link_state_machine::real_link_preserves_the_seam_invariant",
    "foreign_link_state_machine::real_revoke_under_a_live_foreign_link_preserves_the_seam_invariant",
    "gic_declared_residues::a_redistributor_banked_copy_reads_zero_in_the_distributor",
    "gic_declared_residues::a_res0_write_enables_nothing",
    "gic_declared_residues::an_unmodelled_distributor_register_is_still_refused",
    "gic_declared_residues::exactly_one_redistributor_and_it_reports_last",
    "gic_declared_residues::redistributor_pending_and_active_read_zero",
    "gic_declared_residues::routing_an_spi_is_recorded_and_changes_no_enable",
    "gic_declared_residues::spi_pending_and_active_are_accepted_and_read_zero",
    "grant_refcount::map_then_unmap_restores_counts",
    "grant_refcount::writable_exceeds_maps_preserved_under_map",
    "grant_refcount::writable_exceeds_maps_preserved_under_unmap",
    "grant_state_machine::real_map_preserves_first_violation_bounded",
    "p2m_write_xor_execute::a_writable_frame_refuses_an_executable_leaf",
    "p2m_write_xor_execute::executable_frame_stays_wx_under_a_symbolic_leaf",
    "p2m_write_xor_execute::writable_frame_stays_wx_under_a_symbolic_leaf",
    "partition::a_window_top_reservation_fits_4_slots",
    "partition::an_in_window_address_belongs_to_that_slot_2_slots",
    "partition::an_in_window_address_belongs_to_that_slot_4_slots",
    "partition::domain_ids_are_injective_and_never_dom0",
    "partition::frame_and_table_runs_are_disjoint_2_slots",
    "partition::frame_and_table_runs_are_disjoint_3_slots",
    "partition::frame_and_table_runs_are_disjoint_4_slots",
    "partition::owner_of_is_exactly_the_containing_window_2_slots",
    "partition::owner_of_is_exactly_the_containing_window_4_slots",
    "partition::windows_are_pairwise_disjoint_2_slots",
    "partition::windows_are_pairwise_disjoint_3_slots",
    "partition::windows_are_pairwise_disjoint_4_slots",
    "partition::windows_stay_inside_the_backed_ram_2_slots",
    "partition::windows_stay_inside_the_backed_ram_3_slots",
    "partition::windows_stay_inside_the_backed_ram_4_slots",
    "pending_set_algebra::a_bit_round_trips_and_is_exactly_one_bit",
    "pending_set_algebra::lowest_set_is_the_minimum_member_and_none_only_when_empty",
    "pending_set_algebra::the_word_index_of_any_nameable_intid_is_in_range",
    "smmu_stream_binding::a_binding_that_cannot_be_named_exactly_is_refused_and_writes_nothing",
    "smmu_stream_binding::a_bound_stream_names_exactly_the_domain_it_was_given",
    "smmu_stream_binding::binding_a_stream_to_a_domain_leaves_every_other_denied",
    "smmu_stream_binding::no_entry_decodes_as_a_binding_unless_it_is_a_stage2_ste",
    "smmu_stream_binding::rebinding_a_stream_leaves_no_trace_of_the_previous_domain",
    "smmu_stream_binding::the_device_and_the_cpu_walk_under_one_regime",
    "smmu_stream_binding::the_vttbr_seam_recovers_the_table_and_the_vmid",
    "smmu_stream_binding::unbinding_a_domain_binding_restores_the_deny",
    "smmu_stream_derivation::a_map_that_aliases_two_devices_onto_one_entry_is_refused",
    "smmu_stream_derivation::a_refused_derivation_leaves_the_table_denying_every_stream",
    "smmu_stream_derivation::a_swept_holder_leaves_no_stream_bound_and_spares_the_others",
    "smmu_stream_derivation::the_derivation_is_a_function_of_the_relation_alone",
    "smmu_stream_derivation::the_derived_table_binds_exactly_the_assigned_streams",
    "smmu_stream_derivation::the_refinement_check_is_the_property_and_can_fail",
    "smmu_stream_table::a_bind_touches_only_its_own_entry",
    "smmu_stream_table::an_out_of_range_bind_changes_no_word",
    "smmu_stream_table::an_ste_permits_iff_valid_and_not_configured_to_abort",
    "smmu_stream_table::an_under_allocated_table_denies_every_streamid",
    "smmu_stream_table::binding_one_stream_leaves_every_other_denied",
    "smmu_stream_table::the_constructors_decode_to_their_names",
    "smmu_stream_table::the_deployed_stream_table_denies_every_streamid",
    "smmu_stream_table::the_register_encodings_match_the_table_they_describe",
    "smmu_stream_table::unbind_restores_deny_for_every_streamid",
    "smmu_stream_table::zeroed_stream_table_denies_every_streamid",
    "stage2_device_region::device_block_encodes_as_device_ngnrne_xn_identity",
    "stage2_device_region::normal_memory_never_decodes_as_a_device_block",
    "stage2_device_region::validate_ok_implies_device_disjoint_from_ram_leaves",
    "stage2_device_region::validate_ok_implies_regions_pairwise_disjoint",
    "stage2_encoding::data_leaves_are_always_execute_never",
    "stage2_encoding::encode_leaf_descriptors_follow_the_seam",
    "stage2_encoding::image_block_is_always_readonly_and_executable",
    "stage2_encoding::page_encoding_round_trips",
    "stage2_encoding::readonly_never_decodes_as_writable",
    "stage2_encoding::rx_leaf_decodes_executable_and_read_only",
    "stage2_encoding::table_encoding_round_trips",
    "stage2_encoding::the_exemption_is_the_sole_writable_and_executable_leaf",
    "stage2_refinement::a_constructed_span_conflict_is_rejected",
    "stage2_refinement::a_reported_span_conflict_is_real",
    "stage2_refinement::a_span_conflict_state_maps_only_authorized_frames",
    "stage2_refinement::a_writable_leaf_is_never_backed_by_a_readonly_grant",
    "stage2_refinement::an_accepted_map_has_no_span_conflict",
    "stage2_refinement::an_unauthorized_frame_is_never_mapped",
    "stage2_refinement::emitted_leaf_map_is_always_authorized",
    "stage2_refinement::without_the_foreign_link_premise_the_checker_fires",
    "vgic_active_lr::an_active_list_register_is_occupied_but_not_pending",
    "vgic_cpu_interface::a_free_list_register_is_left_exactly_as_it_was",
    "vgic_cpu_interface::a_physical_intid_is_refused_exactly_when_it_cannot_be_named",
    "vgic_cpu_interface::a_purely_virtual_injection_carries_no_physical_claim",
    "vgic_cpu_interface::a_release_demotes_and_disturbs_nothing_else",
    "vgic_cpu_interface::a_release_is_idempotent",
    "vgic_cpu_interface::a_surviving_hardware_mapping_can_only_be_in_a_free_slot",
    "vgic_cpu_interface::an_encoded_hardware_mapping_decodes_to_exactly_what_was_asked",
    "vgic_cpu_interface::an_encoded_list_register_is_never_free",
    "vgic_cpu_interface::release_demotes_exactly_the_occupied_hardware_mappings",
    "vgic_cpu_interface::the_properties_hold_for_any_live_bank_length",
];

/// **Run the Kani corpus and check it contains EXACTLY [`KANI_HARNESSES`].**
///
/// Replaces the bare `cargo kani …` CI step rather than adding to it, so the count costs no extra
/// run. Checks three things, and the middle one is what a count alone would miss:
///
/// * every expected harness was actually checked — a deletion is red;
/// * no unexpected harness was checked — a harness added without a line here is red, so the list
///   cannot silently fall behind the corpus it claims to describe;
/// * Kani's own tally reports zero failures and a total matching the list.
fn kani_harnesses() -> bool {
    let Some((success, text)) = run_capturing(
        "cargo",
        &[
            "kani",
            "-p",
            "hv-verify",
            "-j",
            "4",
            "--output-format=terse",
        ],
    ) else {
        eprintln!("kani-harnesses: cannot run cargo kani");
        return false;
    };
    if !success {
        eprintln!("kani-harnesses: FAIL — cargo kani exited non-zero (its output is above).");
        return false;
    }

    let mut seen: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split("Checking harness ").nth(1))
        .filter_map(|r| r.split("...").next())
        .map(str::trim)
        .collect();
    seen.sort_unstable();
    seen.dedup();

    let mut ok = true;
    for want in KANI_HARNESSES {
        if !seen.contains(want) {
            eprintln!("kani-harnesses: FAIL — expected harness never ran: {want}");
            ok = false;
        }
    }
    for got in &seen {
        if !KANI_HARNESSES.contains(got) {
            eprintln!(
                "kani-harnesses: FAIL — harness ran but is not in KANI_HARNESSES: {got}. Add it, \
                 so the list cannot fall behind the corpus."
            );
            ok = false;
        }
    }
    // `Complete - N successfully verified harnesses, M failures, T total.`
    match text.split("Complete - ").last().and_then(|t| {
        let mut it = t.split_whitespace();
        let n = it.next()?.parse::<usize>().ok()?;
        Some(n)
    }) {
        Some(n) if n == KANI_HARNESSES.len() => {
            eprintln!("kani-harnesses: OK — {n} harnesses, all named in KANI_HARNESSES");
        }
        Some(n) => {
            eprintln!(
                "kani-harnesses: FAIL — Kani verified {n} harnesses, KANI_HARNESSES names {}",
                KANI_HARNESSES.len()
            );
            ok = false;
        }
        None => {
            eprintln!("kani-harnesses: FAIL — no `Complete - N successfully verified` tally found");
            ok = false;
        }
    }
    ok
}

/// ★★ ⑳ — **HOW MANY OBLIGATIONS EACH VERUS FILE DISCHARGES, pinned.**
///
/// ⚠ **The gate this closes: `proofs.yml`'s Verus job checks EXIT STATUS ONLY.** It runs
/// `verus --crate-type=lib` over every file and fails if one does not discharge — which is
/// necessary and, on its own, blind to a proof being **deleted**. Removing `ni_theorem_b`, the
/// confidentiality half of the Tier-D headline, leaves its file verifying `19 verified, 0 errors`
/// and the job **green**. MEASURED, not supposed: see the kill probe in
/// `docs/TIER-D-NONINTERFERENCE.md`.
///
/// That is design-lesson #212's shape at the gate layer — a theorem nothing counts is
/// indistinguishable from a theorem that is gone — and #215's — a checker that reports success when
/// it has nothing to check.
///
/// **The counts were MEASURED on the pinned release** (`0.2026.07.12.0b42f4c`, the same build
/// `proofs.yml` and `deep-verify.yml` install), and total **117**, which is the number
/// `hv-verify/verus/README.md` and the project's own records have tracked by hand.
///
/// ⚠ **Raising a number here is a normal part of adding a proof; LOWERING one is a claim that a
/// proof should no longer exist, and belongs in the commit message.**
const VERUS_OBLIGATIONS: &[(&str, u32)] = &[
    ("control_forest_acyclic", 8),
    ("device_assignment_preservation", 6),
    ("foreign_link_preservation", 9),
    ("frame_lemma", 5),
    ("mislevelled_link_preservation", 29),
    ("noninterference_instantiation", 20),
    ("noninterference_theorem", 5),
    ("read_closure", 2),
    ("refcount_mismatch", 8),
    ("stage2_leaf_authorized", 8),
    ("step_consistency", 3),
    ("unwinding_control", 3),
    ("unwinding_create", 2),
    ("unwinding_destroy", 7),
    ("unwinding_signal", 2),
];

/// **Check every Verus file discharges EXACTLY the obligations [`VERUS_OBLIGATIONS`] expects.**
///
/// Finds `verus` via `$VERUS` or `PATH`. Both directions are checked, and the second is the one a
/// soundness-only version would miss:
///
/// * every file in the table verifies, with the expected count — a deleted or weakened proof is red;
/// * every `.rs` in `hv-verify/verus/` is IN the table — so deleting a whole file is red too, which
///   a per-entry loop over the table alone would sail straight past.
fn verus_counts() -> bool {
    let verus = std::env::var("VERUS").unwrap_or_else(|_| "verus".to_string());
    let dir = std::path::Path::new("hv-verify/verus");

    let mut on_disk: Vec<String> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "rs"))
            .filter_map(|e| {
                e.path()
                    .file_stem()
                    .map(|s| s.to_string_lossy().into_owned())
            })
            .collect(),
        Err(e) => {
            eprintln!("verus-counts: cannot read {}: {e}", dir.display());
            return false;
        }
    };
    on_disk.sort();

    let mut ok = true;
    for name in &on_disk {
        if !VERUS_OBLIGATIONS.iter().any(|(n, _)| n == name) {
            eprintln!(
                "verus-counts: FAIL — hv-verify/verus/{name}.rs is not in VERUS_OBLIGATIONS. A \
                 proof file the table does not name is a proof file nothing counts."
            );
            ok = false;
        }
    }

    for (name, want) in VERUS_OBLIGATIONS {
        let path = dir.join(format!("{name}.rs"));
        if !path.exists() {
            eprintln!(
                "verus-counts: FAIL — {} is in the table and MISSING on disk",
                path.display()
            );
            ok = false;
            continue;
        }
        let Some((success, text)) =
            run_capturing(&verus, &["--crate-type=lib", &path.to_string_lossy()])
        else {
            eprintln!("verus-counts: cannot run `{verus}` (set $VERUS or put it on PATH)");
            return false;
        };
        // `verification results:: N verified, M errors`
        let got = text
            .split("verification results::")
            .nth(1)
            .and_then(|t| t.split_whitespace().next())
            .and_then(|n| n.parse::<u32>().ok());
        if !success {
            eprintln!("verus-counts: FAIL — {name}: verus exited non-zero (output above).");
            ok = false;
            continue;
        }
        match got {
            Some(n) if n == *want => {
                eprintln!("verus-counts: OK — {name}: {n} verified");
            }
            Some(n) => {
                eprintln!(
                    "verus-counts: FAIL — {name}: {n} verified, expected {want}. A LOWER count \
                     means a proof was deleted or weakened; the exit-status-only gate cannot see it."
                );
                ok = false;
            }
            None => {
                eprintln!(
                    "verus-counts: FAIL — {name}: no `verification results::` line; verus \
                           did not complete. Output:\n{text}"
                );
                ok = false;
            }
        }
    }
    let total: u32 = VERUS_OBLIGATIONS.iter().map(|(_, n)| n).sum();
    eprintln!(
        "verus-counts: {} — {} files, {total} obligations",
        if ok { "OK" } else { "FAIL" },
        VERUS_OBLIGATIONS.len()
    );
    ok
}

/// Run a command inheriting stdio, returning whether it succeeded.
fn run(program: &str, args: &[&str]) -> bool {
    run_env(program, args, &[])
}

/// Like [`run`], but with the child's **working directory** set.
///
/// ⚠ **Needed because cargo discovers `.cargo/config.toml` from the WORKING DIRECTORY, not from
/// `--manifest-path`.** `fvp-probe` keeps both its target *and* its linker script (`-C
/// link-arg=-Tlink.ld`) there, so the `--manifest-path` form every other task in this file uses
/// would silently drop the linker script and build something that is not what a developer builds.
///
/// Restating those flags here instead would be a second copy of the crate's own configuration —
/// design-lesson #230 — and the copy is what goes stale. So the gate runs **the command a developer
/// runs, in the directory they run it in**.
fn run_in(dir: &str, program: &str, args: &[&str]) -> bool {
    run_in_env(dir, program, args, &[])
}

/// Like [`run_in`], with extra environment variables set for the child.
///
/// Rustdoc's warning bar is set through `RUSTDOCFLAGS`, not through a `--` passthrough the way
/// clippy's is — `cargo doc -- -D warnings` is rejected outright with *"unexpected argument"*. This
/// exists so [`fvp_lint`] can hold rustdoc to the same bar [`metal_doc`] already does, by the same
/// mechanism.
fn run_in_env(dir: &str, program: &str, args: &[&str], env: &[(&str, &str)]) -> bool {
    eprintln!("$ (cd {dir} && {program} {})", args.join(" "));
    let mut cmd = Command::new(program);
    cmd.args(args).current_dir(dir);
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.status().map(|s| s.success()).unwrap_or(false)
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
