// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! Baleen's task runner. Invoke as `cargo xtask <task>` (see `.cargo/config.toml`).
//!
//! ★ **This crate is where every gate lives.** Each corpus the project pins — the Kani harnesses by
//! name, the Verus obligations by count, the exhaustive sweeps, the boot markers, the README's
//! numbers, the docs' citations and index — is a function below, and each carries a **universe
//! check**: an enumeration of the covered set made independently of the table claiming to cover it
//! (#243). If you want to know what Baleen actually enforces rather than what it claims, read here.
//!
//! `cargo xtask ci` is the real entry point and runs what CI runs. `metal-lint`, `fvp-lint`,
//! `kani-harnesses` and `verus-counts` are separate — different toolchains, and Kani costs minutes.
//!
//! ⚠ Its own doc said *"deliberately tiny for M1 — it grows to cover `hv-metal` cross-builds and
//! the `hv-fuzz` targets as those milestones land"* until 3,500 lines after those milestones landed.
//! A file's module doc is the claim most likely to be false, because nothing reads it on the way
//! past (#240).

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
        // Metal (M5 Arc 5e): boot REAL aarch64 Linux under hv-metal — `linux::NUM_GUESTS` (2)
        // unmodified kernels, isolated from each other, not one. ⚠ This said "a single EL1 guest"
        // until 2026-08-11; see the sweep note in `hv-metal/src/main.rs`. ★ And the count is
        // per-CONFIGURATION: `LinuxBoot::Monitor` gives one slot a bare-metal monitor partition
        // instead of a kernel, so it loads blobs for fewer slots than the machine has.
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
            let monitor = qemu_linux(true, LinuxBoot::Monitor);
            shipped && faulted && looped && smmu && monitor
        }
        // The mixed-criticality boot alone, for working on the monitor without paying the other
        // four. Same reasoning as `qemu-linux-smmu`: a named task, not a local-only escape hatch —
        // it is the fifth configuration of the REQUIRED `qemu-linux-test` above.
        "qemu-linux-monitor" => qemu_linux(true, LinuxBoot::Monitor),
        // ⑲-1b — the same boot `qemu-linux-test` now runs as its fourth configuration, kept as a
        // named task for running it alone during SMMU work. It is NOT a local-only escape hatch:
        // see `LINUX_SMMU_MARKERS` for why that is no longer needed.
        "qemu-linux-smmu" => qemu_linux(true, LinuxBoot::Smmu),
        "metal-lint" => metal_lint(),
        "fvp-lint" => fvp_lint(),
        "doc-markers" => doc_markers(),
        "doc-counts" => doc_counts(),
        "doc-paths" => doc_paths(),
        "doc-index" => doc_index(),
        "doc-tasks" => doc_tasks(),
        "doc-modules" => doc_modules(),
        "seam-census" => seam_census(),
        "hvcall-census" => hvcall_census(),
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
                // ⑳-g: the counts the README states about the five evidence corpora. Cheap (one
                // file read) and it belongs beside `doc_markers`, which polices the same file for
                // the same reason — prose quoting the gates must stay true to them.
                && doc_counts()
                // ⑳-h: every repo path the docs cite must still resolve.
                && doc_paths()
                // ⑳-i: the docs index must still describe the whole of docs/.
                && doc_index()
                // ⑳-l: a README enumerating a directory must enumerate all of it, and
                // `--help` must name every task that exists.
                // ⑳-k: every `cargo xtask` command the docs name must exist.
                && doc_tasks()
                && doc_modules()
                && help_covers_tasks()
                // ㉙: the hypercall seam census. Cheap (six file reads) and it belongs on EVERY PR
                // rather than only proof-path ones, because the thing it catches — a new operation
                // placed above the seam, where no HvCall enumeration reaches it — arrives in
                // ordinary feature work and is silent in every other gate.
                && seam_census()
                // ㉙: and the generator that claims the whole hypercall surface must name all of
                // it. Same family as `seam-census` — both ask whether a coverage claim is gated or
                // merely audited — but a different question, so a different task rather than a
                // second obligation hidden under the first one's name.
                && hvcall_census()
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
                 ci     THE entry point — fmt, clippy -D warnings, test, doc, the deep sweeps,\n  \
                 \u{20}      the proof-gate test, and every doc-* gate below\n  \
                 doc-markers  assert every boot marker a doc QUOTES is still one the gates check\n  \
                 doc-counts   assert the README's corpus counts and proof-to-code ratio match the gates\n  \
                 doc-paths    assert every path the docs cite, and every link they carry, resolves\n  \
                 doc-index    assert docs/README.md classifies every document in docs/\n  \
                 doc-tasks    assert every `cargo xtask` command the docs name really exists\n  \
                 doc-modules  assert a README enumerating a directory enumerates ALL of it\n  \
                 seam-census  assert every hv-core transition is hypercall-reachable, or DECLARED above the seam\n  \
                 hvcall-census  assert the fuzz target that drives HvCall constructs EVERY variant\n  \
                 verus-counts assert every Verus file discharges the obligations it is expected to\n  \
                 kani-harnesses  run the Kani corpus and assert it contains exactly the expected harnesses\n  \
                 sweeps assert the deep exhaustive-sweep corpus is exactly the expected one\n  \
                 qemu   boot hv-metal under QEMU (AArch64/EL2, interactive)\n  \
                 qemu-test  headless QEMU boot smoke-test (the metal CI check)\n  \
                 qemu-linux      boot a REAL Linux kernel under hv-metal (interactive demo)\n  \
                 qemu-linux-test the same boot, headless, asserting its markers (a CI check)\n  \
                 qemu-linux-smmu just the SMMU boot configuration, run alone\n  \
                 qemu-linux-monitor just the mixed-criticality boot (bare-metal monitor beside Linux)\n  \
                 metal-lint fmt --check + clippy + rustdoc, all -D warnings, for hv-metal ({} feature configs)\n  \
                 fvp-lint   the same bar for BOTH standalone probes (build only — CI cannot run the AEM or a board)",
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
    /// ★ **The MIXED-CRITICALITY configuration:** slot [`MONITOR_SLOT`] carries `hv-metal`'s
    /// bare-metal monitor payload instead of a second Linux kernel, so an unmodified kernel and a
    /// small analyzable partition time-slice one pCPU.
    ///
    /// The machine is the shipped one; what changes is that this boot loads blobs for **fewer slots
    /// than the machine has**, because the monitor's payload is copied out of hv-metal's own
    /// `.rodata` and needs no external artifact, device tree or initramfs.
    Monitor,
}

/// The guest slot carrying the bare-metal monitor under [`LinuxBoot::Monitor`].
///
/// ⚠ **This is a SECOND declaration of a fact `hv-metal::linux::MONITOR_SLOT` owns**, and it cannot
/// be folded into one: `hv-metal` is workspace-excluded and does not link for the host, which is the
/// same wall the guest-RAM addresses hit (see the memory-contract note above). It is bound the same
/// way they are — **at RUN time, by a marker**. [`LINUX_MONITOR_MARKERS`] asserts hv-metal's own
/// `guestimage n/a: dom 2 …` line, so a disagreement about which slot is bare-metal fails the gate
/// rather than producing a guest that finds no kernel where one was promised.
const MONITOR_SLOT: u64 = 1;

/// Whether guest `slot` carries a Linux payload in this configuration — the loader's half of the
/// question [`MONITOR_SLOT`] describes. Total over the boots this file can launch.
fn slot_runs_linux(boot: LinuxBoot, slot: u64) -> bool {
    !(boot == LinuxBoot::Monitor && slot == MONITOR_SLOT)
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
    //
    // ⚠ **The monitor configuration renders a DTB for FEWER slots than it has**, so the slot each
    // path belongs to is carried explicitly rather than taken from the vector's index. Index
    // alignment would still be correct today — the monitor sits on the LAST slot — and would break
    // silently the moment it did not, which is the kind of coincidence this file has been burned by.
    let mut dtbs: Vec<(u64, PathBuf)> = Vec::new();
    for slot in 0..NUM_GUESTS {
        if !slot_runs_linux(boot, slot) {
            continue;
        }
        match render_guest_dtb(task, &dir, slot, initrd_size, boot) {
            Some(path) => dtbs.push((slot, path)),
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
    for (slot, dtb) in &dtbs {
        let at = guest_load_addrs(*slot);
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
        // Byte-identical for the same reason, one axis over: the Linux partition must not be able to
        // tell that its PEER is a bare-metal monitor rather than a second kernel. Its device tree
        // describes its own window and its own devices, neither of which the payload swap touches.
        LinuxBoot::Monitor => "",
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
    //
    // ⚠ **The COUNTS in this line moved from prose to a derivation, and this marker is what pins
    // them.** hv-metal used to print `{NUM_GUESTS} REAL … kernels`, which silently assumed every
    // slot runs Linux; the `monitor` configuration makes that false, so the banner now counts
    // payloads. Asserting the rendered result here is what keeps the derivation honest — a census
    // that started miscounting would change this string rather than merely printing a wrong number.
    "baleen: M5 Arc 5e — booting 2 REAL aarch64 Linux kernel(s) + 0 bare-metal monitor \
     partition(s) as EL1 guests time-slicing ONE pCPU (dom 1 owns 0x48000000..0x64000000, dom 2 \
     owns 0x64000000..0x80000000)",
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
    // ⚠ The closing line's counts are now a census over payloads rather than `NUM_GUESTS`, so this
    // boot asserts `2 … + 0 …` — and the explicit ZERO is the useful half: the shipped transcript
    // now states that no slot was swapped out for a bare-metal partition, which it previously could
    // not say at all. The mixed boot asserts `1 … + 1 …` in `LINUX_MONITOR_MARKERS`.
    "baleen: every partition has powered off — 2 unmodified kernel(s) and 0 bare-metal monitor \
     partition(s) ran isolated on hv-metal's EL2, time-slicing one pCPU, and shut down through the \
     same PSCI SYSTEM_OFF path",
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
    //
    // ⚠ **This sentence used to say "every guest booted an unmodified Linux to userspace", and it
    // became FALSE the day a slot stopped running one** — the mixed-criticality boot printed it and
    // passed, because `dmapad OK` is a required marker here and not a forbidden one, so nothing
    // compares it against the machine. Found by reading a transcript. The claim now matches what the
    // check performs (nobody wrote the pad); the per-payload REASON is printed after this prefix,
    // which is why the pin stops here.
    "baleen: dmapad OK: every partition powered off without writing one byte of the 2048 KiB at \
     the top of its own window",
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
/// ⚠ **`every partition has powered off` is deliberately ABSENT**, and its absence is checked
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
    // ⚠⚠ **A FORBIDDEN MARKER GOES VACUOUS SILENTLY, WHICH IS WHY THIS ONE IS CALLED OUT.** The
    // summary line was reworded (its counts became a payload census), and a stale string here would
    // have kept passing forever — "absent" is the pass condition, and a string the boot can no
    // longer print is absent for the wrong reason. A required marker screams when it rots; a
    // forbidden one goes quiet. **Reword the hv-metal line and this entry in the same commit.**
    "baleen: every partition has powered off",
    "baleen: dom 1 issued PSCI SYSTEM_OFF",
];

/// Strings the **mixed-criticality** boot must NOT show, on top of [`LINUX_FORBIDDEN`].
///
/// ⚠⚠ **Its own list rather than an addition to [`LINUX_FORBIDDEN`], and that is lesson #285 applied
/// rather than merely written down.** `baleen: observe FAIL` can only be printed by the `monitor`
/// configuration — hv-metal's observation code does not exist in the other four builds. Putting it
/// in the shared list would buy **one real check and four vacuous ones**, and a forbidden marker
/// that the machine cannot print passes for the wrong reason. Scoped here, every run of it is a
/// check that could actually fail.
///
/// `observe FAIL` covers all four failure paths at once: the grant refused, the view not
/// identity-mapped / not read-only / not execute-never, the vacated frame still mapped, and — the
/// one that matters most — the monitor taking a **READ** fault inside its own observation window,
/// which is the blinded-monitor condition #193 spent a whole rung making impossible.
const LINUX_MONITOR_FORBIDDEN: &[&str] = &["baleen: observe FAIL"];

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

/// The mixed-criticality boot's corpus — a bare-metal monitor partition beside a real Linux guest.
///
/// **Written against a captured transcript, not from the source**: every string below was read off a
/// real run before it was pinned here.
///
/// ## What this corpus asserts, in three groups
///
/// **1 — the machine really is mixed.** The banner's derived counts, the payload deposit, and the
/// `guestimage n/a` line together say one slot was given a kernel and the other was not. The counts
/// are rendered from hv-metal's own `payload_of` census, so a census that started lying would change these strings.
///
/// **2 — the monitor really RAN, as a scheduled EL1 partition.** Its console lines arrive through
/// *its own* emulated PL011 (`[dom 2] …`, tagged by the model instance that received the byte), it
/// was entered by a context restore rather than an `eret`, and it retired through the shared PSCI
/// path. ★ **The load-bearing one is the WFI count**: `4 WFIs trapped, 4 of them yielded the pCPU to
/// a peer` is EL2's own tally of the payload's four observe-and-yield rounds, so it is a number
/// produced by the scheduler about a loop written in the guest — the two halves cannot agree by
/// accident, and one line of output could not produce it.
///
/// **3 — the Linux partition was NOT degraded by sitting beside it.** Dom 1's full driver-witness
/// set is asserted unchanged: emulated console to userspace, forwarded ticks, emulated GIC, mediated
/// SGIs, routed SPIs, and the peer-fault refusal. That is what makes this a mixed-criticality claim
/// rather than a boot with one guest missing.
///
/// ⚠ **Its own list rather than a filter over [`LINUX_MARKERS`], for the reason
/// [`LINUX_FAULT_MARKERS`] is:** dom 2 does not run Linux here, so a large part of that corpus is
/// *legitimately* absent — and a filter deciding which part by matching `"dom 2"` would be a
/// heuristic silently choosing what the gate asserts. Two of its lines name both domains and have to
/// be **replaced** rather than dropped, which a filter cannot express at all.
///
/// ⚠ **What is NOT asserted here, stated so the corpus is not read as more than it is:** dom 2's
/// vtimer / vgic / vsgi / vspi / irqconfine / perguest witnesses. A partition with no drivers
/// generates no driver traffic, so those read zero *correctly*. hv-metal prints one
/// `driverwitness n/a` line naming every one of them and the slot it exempted — and **that line is
/// asserted below**, so the exemption cannot become silent.
///
/// ⚠⚠ **THIS PARAGRAPH SAID "THIS BOOT ESTABLISHES CO-RESIDENCY, NOT OBSERVATION" UNTIL ㉗, and it
/// pointed at a `peer OK … DISJOINT` marker that is no longer in this array.** Kept as a correction:
/// it was true for exactly one rung, and a marker corpus whose doc describes the previous rung's
/// claims is how a reader concludes the gate checks something it does not.
///
/// **㉗ made the monitor observe**, so this corpus now pins the *replaced* disjointness sentence
/// (the one in which the word DISJOINT does not appear) plus the channel's three voices.
///
/// ⚠ **What is still NOT claimed:** the monitor observes and **cannot influence** — no channel out,
/// no actuator. And the policy partition can starve it by writing nothing, which is denial rather
/// than deception and is not detected here.
const LINUX_MONITOR_MARKERS: &[&str] = &[
    // ── 1. the machine is mixed, and the counts are derived ──
    "baleen: M5 Arc 5e — booting 1 REAL aarch64 Linux kernel(s) + 1 bare-metal monitor \
     partition(s) as EL1 guests time-slicing ONE pCPU (dom 1 owns 0x48000000..0x64000000, dom 2 \
     owns 0x64000000..0x80000000)",
    // The payload deposit. The byte count is NOT pinned — it is whatever the assembler produced, and
    // pinning it would redden on every wording change to a string inside the blob.
    "baleen: monitor OK: dom 2 carries the bare-metal monitor payload —",
    "from EL2's own .rodata, no external image and no device tree; it runs 4 observe-and-yield \
     rounds against its peer and then powers off",
    "baleen: guestimage OK: dom 1 — Image 'ARM\\x64' 34 MiB, relocatable, at 0x48000000; DTB \
     0xd00dfeed at 0x4b000000; gzip initramfs at 0x4c000000",
    "baleen: guestimage n/a: dom 2 carries no loaded image",
    // Both images are still built and still disjoint — the payload swap changes what a window HOLDS,
    // never who may reach it.
    "baleen: linux model built for dom 1 — 224 super-span leaves (448 MiB at 0x48000000) across 28 L2-pinned tables, into stage-2 set 0",
    "baleen: linux model built for dom 2 — 224 super-span leaves (448 MiB at 0x64000000) across 28 L2-pinned tables, into stage-2 set 1",
    //
    // ⚠⚠ **㉗ REPLACED THIS LINE RATHER THAN QUALIFYING IT, and the marker follows.** ㉖ asserted the
    // shipped boot's `DISJOINT` here, because the monitor observed nothing. ㉗ gives it a read-only
    // view of one frame, so that sentence is no longer true of this configuration — and a footnote
    // on the strong wording is how a reader ends up quoting the strong half of a weakened guarantee.
    // hv-metal prints a different sentence for this boot, in which the word DISJOINT does not
    // appear, and this corpus pins that one.
    "baleen: peer OK: two domains, two Stage-2 images, disjoint over the guest-RAM window EXCEPT \
     FOR ONE AUTHORIZED, READ-ONLY FRAME",
    // ── 1b. ㉗ — the observation channel, in three independent voices ──
    //
    // The trade that made room for it. Counts derived from `LINUX_SUP_FRAMES_PER_GUEST`, so a
    // partition change would move them together rather than leaving this line stale.
    "baleen: observe: dom 2 spent its own frame at window offset 222",
    "on a READ-ONLY leaf onto dom 1's frame 0 — so it links 223 of its own instead of 224",
    "The leaf is emitted by the PROVEN emitter from an authorized grant; nothing here writes a \
     descriptor",
    // ★ VOICE 1 — the DESCRIPTOR, walked from the emitted tables. Note what is asserted: not merely
    // that the monitor reaches one peer frame, but that the reach is identity-mapped, `S2AP=RO` and
    // execute-never. Until ㉗ this walk read only *reachability* and never `perm` — so the one frame
    // that is now shared is the one frame whose PERMISSION the boot checks.
    "dom 1 reaches its 224 frames and 0 of dom 2's (the policy partition is unaware it is watched, \
     and cannot reach the monitor at all)",
    "dom 2 reaches its own 223, gave up 1 to make room, and reaches EXACTLY 1 of dom 1's — \
     identity-mapped, S2AP=RO and execute-never, asserted from the descriptor",
    // ★★ VOICE 2 — the HARDWARE. A descriptor that says read-only and a CPU that enforces it are
    // different claims, and a permission bit nothing ever tested is one that could have been decoded
    // wrong. The monitor stores through its view; the store takes a Stage-2 permission fault.
    "baleen: observe OK: dom 2 stored through its read-only view at IPA 0x48000038 and the HARDWARE \
     refused it",
    "not because the monitor is trusted not to write, but because the write does not land",
    // ★★★ VOICE 3 — the MONITOR ITSELF, using nothing but its own two loads. It reads the magic,
    // stores poison, reads again, and requires the original value. This is the only one of the three
    // that needs no hypercall and takes nothing on trust from EL2's own report — a refused-but-
    // actually-applied store could pass voices 1 and 2 and cannot pass this one.
    "[dom 2] baleen-monitor: observed the policy partition (ARM\\x64 at its window base) and my \
     store to it did NOT land",
    // ── 2. the monitor ran as a scheduled EL1 partition ──
    //
    // Seeded with no DTB pointer, and entered by a context restore — the two facts that make this a
    // payload swap on the existing entry path rather than a second entry sequence.
    "baleen: dom 2 seeded for its first switch-in — entry 0x64000000, x0 = (none) 0x00000000",
    "it is entered by a context restore, not an eret",
    // Its own words, through its OWN emulated PL011 — the `[dom N]` tag is derived from which model
    // instance received the byte, so these lines cannot be produced by any other slot's device.
    "[dom 2] baleen-monitor: alive — a bare-metal EL1 partition beside an unmodified Linux guest",
    // Every round, individually. `ROUNDS` is 4; asserting each one (rather than only the last) is
    // what makes this a claim about being scheduled REPEATEDLY.
    "[dom 2] baleen-monitor: round 1",
    "[dom 2] baleen-monitor: round 2",
    "[dom 2] baleen-monitor: round 3",
    "[dom 2] baleen-monitor: round 4",
    "[dom 2] baleen-monitor: rounds complete, retiring through PSCI SYSTEM_OFF",
    // ★★ EL2's own count of those rounds. The payload yields with `WFI`; the hypervisor tallies the
    // traps and the handovers. Four rounds written in the guest, four yields counted in EL2.
    "baleen: wfi: dom 2 — 4 WFIs trapped, 4 of them yielded the pCPU to a peer",
    "baleen: idle: dom 2 vcpu 0 — blocked 4 time(s), woken 4",
    // The emulated console, entered by a second NON-LINUX tenant, with the needle exemption stated in
    // the same sentence so it cannot be read as a checked claim.
    "baleen: vpl011 OK: dom 2's console is EMULATED — the bare-metal monitor's own bytes reached \
     dom 2's emulated PL011 DR in EL2",
    "The 'BALEEN-STEP0-OK' needle is NOT checked here and could not be: it is a Linux userspace \
     marker and this partition has no userspace",
    // Retirement through the SAME PSCI path a kernel takes, named for what actually retired.
    "baleen: dom 2 issued PSCI SYSTEM_OFF — the bare-metal monitor partition ran and shut down on \
     hv-metal's EL2",
    "baleen: retire dom 2: powered off cleanly",
    // The exemption itself is a REQUIRED marker: a skipped witness that stopped announcing itself
    // would leave this transcript looking like one where those witnesses had passed.
    "baleen: driverwitness n/a: dom 2 carries the bare-metal monitor payload",
    "the vtimer / vgic / vsgi / vspi / irqconfine / perguest witnesses have nothing to observe for \
     this slot and are NOT asserted for it",
    "baleen: perguest: dom 2 carries the bare-metal monitor payload — its counters are PRINTED \
     below but not asserted",
    // ── 3. the Linux partition is undegraded beside it ──
    "Linux version 6.18.",
    "Run /init as init process",
    "[dom 1] ########## BALEEN-STEP0-OK ##########",
    "baleen: vpl011 OK: dom 1's console is EMULATED — its own userspace's 'BALEEN-STEP0-OK' was \
     written to dom 1's emulated PL011 DR register in EL2",
    "baleen: vtimer OK: dom 1's scheduler tick is FORWARDED —",
    "baleen: vgic OK: dom 1's interrupt controller is EMULATED —",
    "of dom 1's SGIs MEDIATED at EL2 —",
    "baleen: vspi OK: dom 1 re-aimed INTID 33 away from its boot vCPU and EL2 HONOURED it",
    "baleen: vcpu OK: dom 1 was dispatched onto the pCPU",
    // ★ The isolation refusal, with its third conjunct now payload-general: dom 1 is refused dom 2's
    // memory, and what is sitting at that address is dom 2's OWN deposited payload — which is what
    // stops the fault being a boring one about empty space.
    "baleen: peerfault OK: dom 1 touched dom 2's memory at IPA 0x64000fe0 and the HARDWARE refused \
     it",
    "dom 2's own loaded payload (bare-metal payload) is sitting there right now; dom 1 took the \
     abort and kept running",
    // Both partitions retire, and the closing line counts them by payload rather than calling them
    // all kernels.
    "baleen: every partition has powered off — 1 unmodified kernel(s) and 1 bare-metal monitor \
     partition(s) ran isolated on hv-metal's EL2, time-slicing one pCPU, and shut down through the \
     same PSCI SYSTEM_OFF path",
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
        LinuxBoot::Monitor => LINUX_MONITOR_MARKERS.to_vec(),
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
        LinuxBoot::Monitor => LINUX_MONITOR_FORBIDDEN.iter(),
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
        LinuxBoot::Monitor => LINUX_MONITOR_FEATURES,
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
/// As [`LINUX_FEATURES`], for the mixed-criticality boot — slot [`MONITOR_SLOT`] carries the
/// bare-metal monitor payload instead of a second kernel.
const LINUX_MONITOR_FEATURES: &str = "real-linux,selftest,monitor";

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
    // The one-way observation channel. Booted by `boot-test.sh`'s seventh `boot_and_check`, so by
    // this list's own stated invariant — anything a gate boots must be linted — it belongs here
    // from the day it lands rather than being found missing later, which is what ⑳-f cost.
    &["--features", "observe"],
    // ⑲-1 — the combined configuration. It is BUILT AND BOOTED by `qemu-linux-test`'s `Smmu` boot,
    // so by this list's own stated invariant it must be linted; before this rung it was a config
    // that compiled and that no gate ever looked at, which is ⑭b's finding one rung along.
    &["--features", LINUX_SMMU_FEATURES],
    // The mixed-criticality configuration. BUILT AND BOOTED by `qemu-linux-test`'s `Monitor` boot,
    // so it belongs here from the day it lands — the invariant above, applied on arrival rather
    // than discovered missing later, which is exactly what ⑳-f cost.
    &["--features", LINUX_MONITOR_FEATURES],
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

/// Every standalone instrument crate this task keeps healthy.
///
/// ⚠ **`board-probe` was added here in the SAME commit that created it, and that ordering is the
/// point.** `fvp-probe` existed for four milestones before anything built it — #176's finding was
/// literally "the instrument A2 will rest on was built by nothing at all". Adding a second probe
/// without adding it here would have reproduced that exactly, one crate along, which is
/// design-lesson **#262**: extending a rule to a new case is the moment to re-derive it, because
/// the person adding the case is the last one who will re-check the rule's base.
const PROBE_DIRS: &[&str] = &[FVP_DIR, BOARD_PROBE_DIR];

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
///
/// ⚠ **⑯-hw phase 0 generalised it over [`PROBE_DIRS`]** rather than one hardcoded crate, because
/// `board-probe` arrived and a second instrument gated by nothing would have been #176's finding
/// again, one crate along.
///
/// ★ It checks the probes' **health**, never their **results**. A probe's verdicts come from
/// hardware or a model CI does not have, so those stay LOCAL evidence — what this guarantees is that
/// the instrument still compiles, which is the thing that rots silently between uses.
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

/// ★ ⑳-h — **every repo path the docs CITE must resolve.**
///
/// The prose in `docs/`, the root `README.md` and every crate README points at the code constantly —
/// **235 backtick-quoted paths and 67 markdown links across 39 documents** when this was written —
/// and a codebase that moves as much as this one does will eventually point at something that is not
/// there.
///
/// ★★ **TWO citation styles, and they resolve by DIFFERENT rules** — see the second scan below. A
/// backtick citation (`` `hv-metal/src/mmu.rs` ``) is written from the repo root; a markdown link
/// (`[text](QEMU-AND-METAL.md)`) is written relative to the file it sits in. ⚠ The link half was
/// missing at first, and ⑳-i found it the hard way: `docs/README.md` is written entirely in link
/// style, so this gate scanned it and reported **zero** citations while a deliberately broken link
/// in its own reading order passed. A gate for documentation that cannot see the style the newest
/// document is written in is a gate for the past.
///
/// A dead pointer is worse than no pointer: it reads as a discharged reference, so a reader stops
/// looking (design-lesson #263, and #259's sharper form where the reference is live but names the
/// wrong thing).
///
/// ⚠ The crate READMEs were missing from the first version, and they are the ones where that costs
/// most: they are the front doors of the two INSTRUMENTS, whose whole value is that a reader can
/// find and RUN them. A pointer that dies where someone is trying to *execute* something costs more
/// than one in a design doc, not less.
///
/// ## The resolution rule, stated because it is the part that could be wrong
///
/// A citation passes if it resolves **either** from the repo root **or** relative to any one crate
/// directory. The second arm is not laxity — it is how the docs actually cite `hv-metal`'s modules
/// (`` `src/stage2.rs` `` inside a document that is entirely about `hv-metal`), and a checker that
/// rejected those would have produced **eight false positives on its first run** and been switched
/// off. ⚠ It was written naively first and did exactly that; the eight were real files.
///
/// What it therefore does NOT catch: a path that resolves under the *wrong* crate. That is a real
/// gap, and it is the honest trade for a check that does not cry wolf — the same partial-guard
/// bargain ㉔ made, stated rather than glossed.
fn doc_paths() -> bool {
    eprintln!("$ xtask doc-paths");

    // Backtick-quoted tokens containing `/` and ending in an extension the repo uses. Deliberately
    // NOT a general path matcher: prose is full of things that look like paths (`hv-core/src`,
    // `0x40_1000_0000`), and a matcher that guessed would spend its life being tuned.
    const EXTS: &[&str] = &[".rs", ".sh", ".toml", ".yml", ".ld", ".md", ".dts"];
    let crates: Vec<String> = match std::fs::read_dir(".") {
        Ok(d) => d
            .flatten()
            .filter(|e| e.path().is_dir())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| !n.starts_with('.') && n != "target" && n != "docs")
            .collect(),
        Err(e) => {
            eprintln!("doc-paths: cannot list the repo root: {e}");
            return false;
        }
    };

    // ⚠ The crate READMEs are here too, and they were the first thing this check missed. They cite
    // paths as heavily as `docs/` does — `board-probe/README.md` alone names `link.ld`,
    // `src/main.rs` and `qemu-probe.sh` — and they are the front door for the two INSTRUMENTS,
    // whose whole value is that a reader can find and run them. A dead pointer there costs more
    // than one in a design doc, not less.

    // ⑳-j — **every crate must have a front door.** Eight of twelve had none, and they were the
    // eight that carry the claim: a reader arriving at `hv-part` got a directory. The universe is
    // "a directory with a `Cargo.toml`", enumerated here rather than read off the workspace
    // manifest on purpose — `hv-metal`, `hv-fuzz` and the two probes are workspace-EXCLUDED, and
    // an excluded crate is exactly the one whose front door nobody would notice was missing.
    let mut sources: Vec<String> = vec!["README.md".to_string()];
    let mut doorless: Vec<&str> = Vec::new();
    for c in &crates {
        if !std::path::Path::new(c).join("Cargo.toml").exists() {
            continue;
        }
        let readme = format!("{c}/README.md");
        if std::path::Path::new(&readme).exists() {
            sources.push(readme);
        } else {
            doorless.push(c);
        }
    }
    if !doorless.is_empty() {
        doorless.sort_unstable();
        for c in &doorless {
            eprintln!("doc-paths: FAIL — the crate `{c}` has no README.md. It is the front door;");
            eprintln!("                  without one a reader arriving at that directory gets a file listing.");
        }
        return false;
    }
    match std::fs::read_dir("docs") {
        Ok(d) => sources.extend(
            d.flatten()
                .filter_map(|e| e.path().to_str().map(str::to_string))
                .filter(|p| p.ends_with(".md")),
        ),
        Err(e) => {
            eprintln!("doc-paths: cannot list docs/: {e}");
            return false;
        }
    }

    let base = std::path::Path::new(".");
    let mut cited = 0usize;
    let mut linked = 0usize;
    let mut dead: Vec<(String, String)> = Vec::new();
    let mut dead_links: Vec<(String, String)> = Vec::new();
    for src in &sources {
        let Ok(text) = std::fs::read_to_string(src) else {
            eprintln!("doc-paths: cannot read {src}");
            return false;
        };
        for chunk in text.split('`').skip(1).step_by(2) {
            if !chunk.contains('/') || !EXTS.iter().any(|e| chunk.ends_with(e)) {
                continue;
            }
            // Reject anything with whitespace or markup: those are prose, not citations.
            if chunk
                .chars()
                .any(|c| c.is_whitespace() || c == '*' || c == '(')
            {
                continue;
            }
            cited += 1;
            let resolves = std::path::Path::new(chunk).exists()
                || crates
                    .iter()
                    .any(|c| std::path::Path::new(c).join(chunk).exists());
            if !resolves {
                dead.push((src.clone(), chunk.to_string()));
            }
        }

        // ★★ MARKDOWN LINK TARGETS — `](path)` — added because ⑳-i wrote `docs/README.md` entirely
        // in link style and this gate saw **zero** of its links. A gate for documentation that
        // cannot see the citation style the newest document uses is a gate for the past.
        //
        // ⚠ **These resolve by a DIFFERENT rule and it is not a detail**: a markdown link is
        // relative to the FILE it appears in, not to the repo root — `QEMU-AND-METAL.md` inside
        // `docs/` means `docs/QEMU-AND-METAL.md`, and `../README.md` means the root one. The
        // backtick rule above (root, or under any crate) would resolve neither. Two citation
        // styles, two resolution rules, one gate.
        //
        // ★ These are the links a reader CLICKS, so a dead one costs more than a dead backtick: it
        // is the reading order's first instruction failing in the reader's hands.
        let dir = std::path::Path::new(src).parent().unwrap_or(base);
        for (i, _) in text.match_indices("](") {
            let rest = &text[i + 2..];
            let Some(end) = rest.find(')') else { continue };
            let target = rest[..end].trim();
            // Anchors and external links are not this gate's business; a title suffix is stripped.
            let target = target.split(&[' ', '#'][..]).next().unwrap_or("");
            if target.is_empty() || target.contains("://") || target.starts_with("mailto:") {
                continue;
            }
            linked += 1;
            if !dir.join(target).exists() {
                dead_links.push((src.clone(), target.to_string()));
            }
        }
    }

    // ⚠⚠ **THE FLOOR, and it exists because the naive version passed VACUOUSLY.** With the matcher
    // broken — an edit to `EXTS`, a change in quoting convention — `cited` falls to 0, `dead` is
    // empty, and this reported "0 cited repo paths … all resolve" with exit 0: a gate green on no
    // evidence. Design-lesson #215, and the THIRD time this project has needed the same fix
    // (`BOOT_TEST_CONFIGS` in ㉓, `EXPECTED_CASES` in its test suite, now this).
    //
    // ★ A FLOOR rather than an exact pin, deliberately. The citation count moves whenever anyone
    // writes a sentence, so an exact number would fire constantly and be bumped without thought —
    // the failure mode that makes a gate furniture. A floor fires only when the matcher has
    // genuinely stopped working, which is the failure being guarded. Same reasoning as the
    // proof-to-code ratio's two decimals: the granularity that catches the failure without crying
    // wolf.
    //
    // ⚠ Lowering this is a claim that the docs cite substantially less code than they did, and
    // belongs in a commit message.
    const MIN_CITATIONS: usize = 150;
    if cited < MIN_CITATIONS {
        eprintln!(
            "doc-paths: FAIL — only {cited} cited repo paths found, expected at least \
             {MIN_CITATIONS}. The matcher has probably stopped matching (EXTS? quoting?), which \
             would make every later check pass on nothing."
        );
        return false;
    }

    // ⚠ The links get their OWN floor. Sharing one with the backtick citations would let a total
    // collapse of link parsing hide behind 235 healthy backticks — the subset-as-total defect ⑳-g
    // shipped, one level up. A corpus that can fail independently needs a floor of its own.
    const MIN_LINKS: usize = 40;
    if linked < MIN_LINKS {
        eprintln!(
            "doc-paths: FAIL — only {linked} markdown link targets found, expected at least \
             {MIN_LINKS}. The `](...)` scan has probably broken."
        );
        return false;
    }

    if dead.is_empty() && dead_links.is_empty() {
        eprintln!(
            "doc-paths: OK — {cited} backtick-cited paths + {linked} markdown links across {} docs \
             all resolve",
            sources.len()
        );
        return true;
    }
    for (src, c) in &dead {
        eprintln!("doc-paths: FAIL — {src} cites `{c}`, which resolves neither from the repo root");
        eprintln!("                  nor under any crate directory. Renamed, moved, or deleted?");
    }
    for (src, l) in &dead_links {
        eprintln!("doc-paths: FAIL — {src} LINKS to `{l}`, which does not exist relative to that");
        eprintln!("                  file's own directory. This is a link a reader clicks.");
    }
    false
}

/// ★ ⑳-k — **every `cargo xtask <task>` the docs tell a reader to RUN must exist.**
///
/// `doc-paths` checks *paths*; this checks *commands*, and the distinction is the point (#278 — a
/// checker covers the syntax it parses, not the concern its name suggests). A dead path costs a
/// reader a lookup. **A dead command costs them a failed run and the belief that the project does
/// not work** — and it lands at the exact moment they were trying to verify a claim, which is the
/// worst moment this repo has.
///
/// ⚠ Written after the README sweep put a **block of runnable commands** at the top of the most-read
/// file here. **Every cited task resolved on the first run** — the good case, and precisely when a
/// guard is cheapest to install. (The count is deliberately not repeated here: the gate prints it,
/// and a number in prose beside a number in output is the second copy #276 is about. I first wrote
/// "thirteen", which was already wrong by two when it shipped, because my manual grep had covered
/// fewer files than the gate does.)
///
/// ## The direction it checks, and the one it does not
///
/// **Cited ⇒ exists.** The reverse — every task documented somewhere — is deliberately NOT checked:
/// plenty of tasks are internal plumbing (`doc-counts` is run by `ci`, not by people), and a gate
/// demanding they all be advertised would be noise.
///
/// ⚠ **The task universe is every `"…" =>` arm in this file, which is a SUPERSET of `main`'s
/// dispatch** — brace-matching the one `match` would be brittle for no gain. The consequence is
/// stated rather than hidden: this cannot catch a fabricated task name that happens to collide with
/// an arm in some other `match`. It catches every renamed, deleted and mistyped task, which is the
/// population that actually rots.
fn doc_tasks() -> bool {
    eprintln!("$ xtask doc-tasks");

    let Ok(me) = std::fs::read_to_string("xtask/src/main.rs") else {
        eprintln!("doc-tasks: cannot read xtask/src/main.rs");
        return false;
    };
    let mut arms: Vec<&str> = Vec::new();
    for line in me.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix('"') else {
            continue;
        };
        let Some(end) = rest.find('"') else { continue };
        if rest[end + 1..].trim_start().starts_with("=>") {
            arms.push(&rest[..end]);
        }
    }

    let mut docs: Vec<String> = vec!["README.md".to_string()];
    for d in ["docs", "."] {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let pth = e.path();
                if pth.is_dir() {
                    let r = pth.join("README.md");
                    if r.exists() {
                        docs.push(r.to_string_lossy().into_owned());
                    }
                } else if pth.extension().is_some_and(|x| x == "md") {
                    docs.push(pth.to_string_lossy().into_owned());
                }
            }
        }
    }

    let mut cited = 0usize;
    let mut distinct: Vec<String> = Vec::new();
    let mut dead: Vec<(String, String)> = Vec::new();
    for d in &docs {
        let Ok(text) = std::fs::read_to_string(d) else {
            continue;
        };
        for (i, _) in text.match_indices("cargo xtask ") {
            let rest = &text[i + "cargo xtask ".len()..];
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                .collect();
            if name.is_empty() {
                continue;
            }
            cited += 1;
            if !distinct.contains(&name) {
                distinct.push(name.clone());
            }
            if !arms.contains(&name.as_str()) {
                dead.push((d.clone(), name));
            }
        }
    }

    // ⚠⚠ THE FLOOR — #275, and the fifth application. Break the `"cargo xtask "` scan and `cited`
    // falls to 0 with `dead` empty: "0 cited tasks all exist", green on nothing.
    const MIN_CITED_TASKS: usize = 25;
    if cited < MIN_CITED_TASKS {
        eprintln!(
            "doc-tasks: FAIL — only {cited} `cargo xtask` citations found, expected at least \
             {MIN_CITED_TASKS}. The scan has probably broken."
        );
        return false;
    }

    if dead.is_empty() {
        eprintln!(
            "doc-tasks: OK — {cited} `cargo xtask` citations across {} docs name {} distinct tasks, \
             all real",
            docs.len(),
            distinct.len()
        );
        return true;
    }
    for (d, t) in &dead {
        eprintln!(
            "doc-tasks: FAIL — {d} tells a reader to run `cargo xtask {t}`, which is not a task."
        );
        eprintln!("                  A dead command fails in the reader's hands while they are checking a claim.");
    }
    false
}

/// ★ ⑳-l — **a README that ENUMERATES a directory must enumerate ALL of it.**
///
/// ⑳-j gated that every crate *has* a README. Both crates checked here **had one, and both were
/// substantially false**: `hv-metal`'s layout table listed **7 of 28** modules under a status
/// heading frozen three milestones back, and `hv-fuzz`'s target table listed **4 of 7** — `p2m`,
/// `policy` and `sched` invisible since the day they were added.
///
/// ★★ **Existence is not truth**, and a partial table is worse than none: it reads as complete, so
/// a reader stops looking (#263) and nobody notices the corpus drifting. The universe is the
/// directory, enumerated from the filesystem (#279); the table is the README.
///
/// ⚠ **It does NOT check whether the description beside each entry is true.** Membership is what
/// rots mechanically when a file is added; prose needs the diff read. Same bargain `doc-index`
/// states.
fn doc_modules() -> bool {
    eprintln!("$ xtask doc-modules");

    // (readme, directory, what its members are called, floor)
    const ENUMERATED: &[(&str, &str, &str, usize)] = &[
        ("hv-metal/README.md", "hv-metal/src", "module", 25),
        (
            "hv-fuzz/README.md",
            "hv-fuzz/fuzz_targets",
            "fuzz target",
            6,
        ),
    ];

    let mut ok = true;
    for (readme, dir, kind, floor) in ENUMERATED {
        let mut universe: Vec<String> = match std::fs::read_dir(dir) {
            Ok(d) => d
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.ends_with(".rs"))
                .collect(),
            Err(e) => {
                eprintln!("doc-modules: cannot list {dir}: {e}");
                return false;
            }
        };
        universe.sort();

        // ⚠⚠ THE FLOOR — #275, sixth application. A broken `read_dir` empties the universe and
        // every table is trivially complete: "all 0 modules listed", green on nothing.
        if universe.len() < *floor {
            eprintln!(
                "doc-modules: FAIL — only {} .rs files in {dir}, expected at least {floor}. The \
                 enumeration has probably broken, which would make the check below vacuous.",
                universe.len()
            );
            return false;
        }

        let Ok(text) = std::fs::read_to_string(readme) else {
            eprintln!("doc-modules: cannot read {readme}");
            return false;
        };

        let mut missing = 0usize;
        for m in &universe {
            // Cited by any path form — `src/main.rs`, `hv-metal/src/main.rs`, a link target.
            // This checks COVERAGE, not formatting: pinning a rendering would make it a style gate
            // that fires on every rewrite.
            //
            // ⚠⚠ **The leading `/` is load-bearing and a bare filename match would be WRONG.**
            // `pl011.rs` is a substring of `vpl011.rs`, so a README that lists only the emulated
            // one would report the real driver as covered — a false pass on the exact pair most
            // easily confused. Matching `/pl011.rs` cannot collide with `/vpl011.rs`.
            let cited = text.contains(&format!("/{m}"));
            if !cited {
                eprintln!("doc-modules: FAIL — {readme} does not list the {kind} `{m}`.");
                missing += 1;
                ok = false;
            }
        }
        if missing == 0 {
            eprintln!(
                "doc-modules: OK — {readme} lists all {} {kind}s in {dir}",
                universe.len()
            );
        } else {
            eprintln!(
                "doc-modules:      ({missing} of {} missing — a table covering part of a directory \
                 reads as complete.)",
                universe.len()
            );
        }
    }
    ok
}

/// ★★★ ㉙ — **THE HYPERCALL-SEAM CENSUS: which operations the totality gate structurally cannot
/// reach.**
///
/// `hv-core`'s exhaustive coverage argument runs through **one** surface. `HVCALL_VARIANT_COUNT` is
/// machine-checked against `core::mem::variant_count::<HvCall>()`, and `hv-sim`'s enumerator asserts
/// it emits exactly `HVCALL_VARIANT_COUNT - NUM_EXCLUDED` distinct guest variants — so any state
/// machine driven *by a hypercall* is swept exhaustively, and adding a variant without wiring it in
/// breaks that balance loudly. **That is a genuine gate and it covers 45 of the 48 mutating
/// operations in `hv-core`.**
///
/// ⚠⚠ **The other three are not reachable from a hypercall at all, and no enumeration over `HvCall`
/// can ever reach them.** `policy::` sits deliberately *above* the dispatch seam — a guest never
/// asks to be scheduled; the hypervisor's own tick/idle path invokes the policy. So `advance`,
/// `set_weight` and `set_wake_boost` are driven only by hand-written generators, and **that is
/// exactly where ㉘'s defect lived for four arcs**: work conservation was flatly false while three
/// tiers reported green, because the only two generators that could reach the policy drew from the
/// same op alphabet and neither ever moved the affinity axis.
///
/// ★ **So this gate exists to make "above the seam" a fact the build states, not one somebody has to
/// notice.** A new module or method placed above the seam inherits **no** enumerator coverage, and
/// the failure is silent — the new code simply is not swept, and every existing gate stays green.
///
/// ## Why this is a BALANCE and not a search — the design decision worth not re-litigating
///
/// The obvious implementation is to grep `hypervisor.rs` for each operation's name and classify
/// whatever is absent as above-seam. **That is unsound in the dangerous direction.** `p2m` exposes
/// `get`, `put` and `free`; `hypervisor.rs` contains `.get(` and `.put(` on `Vec`/`Option` for
/// entirely unrelated reasons. Those collisions make an above-seam operation look covered — the gate
/// then *under-reports*, which is the failure mode it exists to prevent (design-lesson #281: an
/// under-collecting extraction is a floor-proof failure, and here over-collection is the same defect
/// mirrored).
///
/// So the classification is **declared** and the census **balances**: pin the total number of
/// mutating operations, and pin the above-seam list. Adding a mutating method anywhere — above or
/// below the seam — changes the total and fails this gate, forcing an explicit classification rather
/// than allowing a silent inheritance of "covered". The name-search is kept only in its **safe**
/// direction: a declared above-seam operation that *does* appear in `hypervisor.rs` is a
/// contradiction, and a false positive there costs a spurious failure, never a missed one.
///
/// ⚠ **This is GATE-total, not COMPILER-total, and the difference is real.** `HvCall` is an enum, so
/// its arity is a compiler fact; a set of methods is not, and there is no `variant_count` for `impl`
/// blocks. Pinning counts is therefore the honest ceiling *here* — the compiler-total half belongs
/// with the generators that drive the above-seam surface, not with this census.
fn seam_census() -> bool {
    eprintln!("$ xtask seam-census");

    /// The state-bearing modules. `hypervisor` is the seam itself (classifying it against itself is
    /// meaningless) and `prng` carries no state machine, so neither is a subject.
    const MODULES: &[&str] = &["sched", "policy", "evtchn", "grant", "p2m", "device"];
    /// Every `pub fn(&mut self)` across `MODULES`, measured 2026-08-13.
    const TOTAL_MUTATING_OPS: usize = 48;
    /// ⚠⚠ #275 — a parser that silently stops matching empties the universe and every check below
    /// passes on nothing. Well under the real figure, so refactors do not trip it, but far enough
    /// above zero that a broken extractor cannot read as success.
    const FLOOR: usize = 40;
    /// The operations no `HvCall` can reach. **Each one needs a named generator of its own**, because
    /// the enumerator provably cannot drive it.
    const ABOVE_SEAM: &[&str] = &[
        "policy::advance",
        "policy::set_wake_boost",
        "policy::set_weight",
    ];
    const SEAM: &str = "hv-core/src/hypervisor.rs";
    /// What drives the above-seam surface, since no `HvCall` enumeration can. `scenario.rs` holds
    /// the seeded harnesses (`run_policy`, `run_policy_steady`, `run_policy_max_wait`,
    /// `run_sleeper`); the fuzz target explores the same surface with an unseeded stream.
    const ABOVE_SEAM_GENERATORS: &[&str] =
        &["hv-sim/src/scenario.rs", "hv-fuzz/fuzz_targets/policy.rs"];

    let mut found: Vec<String> = Vec::new();
    for m in MODULES {
        let path = format!("hv-core/src/{m}.rs");
        let Ok(text) = std::fs::read_to_string(&path) else {
            eprintln!("seam-census: FAIL — cannot read {path}");
            return false;
        };
        // The production surface only: a `#[cfg(test)]` module's helpers are not transitions.
        let prod = text
            .split("\nmod tests {")
            .next()
            .unwrap_or(&text)
            .to_string();
        for name in mutating_ops(&prod) {
            found.push(format!("{m}::{name}"));
        }
    }
    found.sort();

    if found.len() < FLOOR {
        eprintln!(
            "seam-census: FAIL — found only {} mutating operations across {} modules, expected at \
             least {FLOOR}. The extractor has probably broken, which would make every check below \
             vacuous.",
            found.len(),
            MODULES.len()
        );
        return false;
    }

    let mut ok = true;

    // (1) THE BALANCE. Any added or removed mutating operation lands here first.
    if found.len() != TOTAL_MUTATING_OPS {
        eprintln!(
            "seam-census: FAIL — {} mutating operations across hv-core, expected \
             {TOTAL_MUTATING_OPS}.\n\
             \x20                  A mutating operation was added or removed. Classify it: if a \
             hypercall can reach it,\n\
             \x20                  the enumerator sweeps it and you need only update \
             TOTAL_MUTATING_OPS. If NOT, it is\n\
             \x20                  ABOVE THE SEAM — nothing sweeps it, and it needs a named \
             generator plus a line in\n\
             \x20                  ABOVE_SEAM. Do not update the count without deciding which.",
            found.len()
        );
        ok = false;
    }

    // (2) The declared above-seam operations must still EXIST. A rename would otherwise leave a
    // dead entry here while the real operation quietly lost its declaration.
    for want in ABOVE_SEAM {
        if !found.iter().any(|f| f == want) {
            eprintln!(
                "seam-census: FAIL — ABOVE_SEAM names `{want}`, which no longer exists. It was \
                 renamed or removed; update the list rather than deleting the obligation."
            );
            ok = false;
        }
    }

    // (3) The safe direction of the name search: a declared above-seam operation must NOT appear at
    // the seam. A false positive here costs a spurious failure; it can never hide a real one.
    let Ok(seam_text) = std::fs::read_to_string(SEAM) else {
        eprintln!("seam-census: FAIL — cannot read {SEAM}");
        return false;
    };
    for want in ABOVE_SEAM {
        let Some((_, name)) = want.split_once("::") else {
            continue;
        };
        if seam_text.contains(&format!(".{name}(")) {
            eprintln!(
                "seam-census: FAIL — `{want}` is declared above the seam but `{SEAM}` appears to \
                 call it. Either it became hypercall-reachable (drop it from ABOVE_SEAM — the \
                 enumerator now sweeps it), or an unrelated method shares its name."
            );
            ok = false;
        }
    }

    // (4) THE OBLIGATION THE OTHER THREE CHECKS ONLY DESCRIBE. Classifying an operation as
    // above-seam says nothing drives it; it has to be *driven* by something, and the enumerator
    // never will. So every declared above-seam operation must be named by at least one declared
    // generator — the check that turns "it needs a named generator" from advice in a failure
    // message into a thing the build enforces.
    for want in ABOVE_SEAM {
        let Some((_, name)) = want.split_once("::") else {
            continue;
        };
        let driven: Vec<&str> = ABOVE_SEAM_GENERATORS
            .iter()
            .copied()
            .filter(|g| std::fs::read_to_string(g).is_ok_and(|t| t.contains(&format!(".{name}("))))
            .collect();
        if driven.is_empty() {
            eprintln!(
                "seam-census: FAIL — `{want}` is above the seam and NO declared generator drives \
                 it: {}.\n\
                 \x20                  Nothing sweeps it and nothing exercises it, so it is \
                 covered by unit tests at best.",
                ABOVE_SEAM_GENERATORS.join(", ")
            );
            ok = false;
        }
    }

    if ok {
        eprintln!(
            "seam-census: OK — {} mutating operations; {} above the hypercall seam ({}), each \
             outside every HvCall enumeration and each driven by a declared generator",
            found.len(),
            ABOVE_SEAM.len(),
            ABOVE_SEAM.join(", ")
        );
    }
    ok
}

/// ★★ ㉙ — **the generator that claims the whole hypercall surface must actually name all of it.**
///
/// `hv-fuzz/fuzz_targets/hypervisor.rs` drives `dispatch` across `HvCall`, so it presents itself as
/// covering the guest-visible surface entire. Its alphabet was a **hand-typed `op % 34`** against a
/// `HVCALL_VARIANT_COUNT` of **35**, and the missing variant was `EvtchnUnmask` — unnamed, ungenerated,
/// and invisible to every gate.
///
/// ⚠ **Severity is low and saying so is part of the finding:** the enumerator sweeps `EvtchnUnmask`
/// exhaustively and `fuzz_targets/evtchn.rs` calls `unmask` directly, so nothing was actually
/// uncovered. **The defect is the drift, not the gap** — a generator's alphabet diverged from the
/// surface it advertises and only a hand diff found it, which is the same shape as the
/// work-conservation defect of #198 one layer down.
///
/// ## The extraction is self-checking, which is what makes this non-vacuous
///
/// The variant list is parsed out of the `pub enum HvCall` block — and then **balanced against
/// `HVCALL_VARIANT_COUNT`**, which the compiler itself checks against `core::mem::variant_count`.
/// So a parser that silently under-collects does not quietly shrink the universe and pass; it
/// disagrees with a compiler fact and fails loudly (#281, handled at the source rather than with a
/// floor guess).
///
/// ⚠ The modulus is checked too, and it has to be: naming every variant is **not sufficient** if the
/// `op % N` that selects them is smaller than the arm count, because the trailing arms are then
/// unreachable and their variants are named but never generated. A future deliberate exclusion
/// belongs in a declared constant here, the way the enumerator declares `NUM_EXCLUDED` — not in a
/// smaller modulus.
fn hvcall_census() -> bool {
    eprintln!("$ xtask hvcall-census");

    const SEAM: &str = "hv-core/src/hypervisor.rs";
    const TARGET: &str = "hv-fuzz/fuzz_targets/hypervisor.rs";

    let (Ok(seam), Ok(target)) = (
        std::fs::read_to_string(SEAM),
        std::fs::read_to_string(TARGET),
    ) else {
        eprintln!("hvcall-census: FAIL — cannot read {SEAM} or {TARGET}");
        return false;
    };

    // The compiler-checked total, read from the source rather than retyped here.
    let Some(declared) = seam
        .split("pub const HVCALL_VARIANT_COUNT: usize = ")
        .nth(1)
        .and_then(|s| s.split(';').next())
        .and_then(|s| s.trim().parse::<usize>().ok())
    else {
        eprintln!("hvcall-census: FAIL — cannot read HVCALL_VARIANT_COUNT from {SEAM}");
        return false;
    };

    // The variants themselves.
    let Some(body) = seam
        .split("pub enum HvCall {")
        .nth(1)
        .and_then(|s| s.split("\n}").next())
    else {
        eprintln!("hvcall-census: FAIL — cannot find the `pub enum HvCall` block in {SEAM}");
        return false;
    };
    let mut variants: Vec<String> = Vec::new();
    for line in body.lines() {
        let t = line.trim_start();
        // A variant opens at four-space indentation with an upper-case name; anything else in the
        // block is a doc comment, an attribute, or a field of the variant above.
        if line.starts_with("    ") && !line.starts_with("     ") {
            let name: String = t
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if name.chars().next().is_some_and(|c| c.is_uppercase()) && !variants.contains(&name) {
                variants.push(name);
            }
        }
    }

    let mut ok = true;

    // (1) The extraction balances against the compiler fact, so it cannot be vacuous.
    if variants.len() != declared {
        eprintln!(
            "hvcall-census: FAIL — parsed {} variants from the enum but HVCALL_VARIANT_COUNT is \
             {declared}. The parser is wrong, not the code; fix it rather than the constant.",
            variants.len()
        );
        return false;
    }

    // (2) Every variant must be named by the generator that claims the whole surface.
    let mut missing: Vec<&str> = Vec::new();
    for v in &variants {
        if !target.contains(&format!("HvCall::{v}")) {
            missing.push(v);
        }
    }
    if !missing.is_empty() {
        eprintln!(
            "hvcall-census: FAIL — {TARGET} drives `dispatch` across HvCall but never constructs \
             {} of {declared} variants: {}.\n\
             \x20                   A generator that covers part of a surface reads as covering all \
             of it.",
            missing.len(),
            missing.join(", ")
        );
        ok = false;
    }

    // (3) The selector must reach every arm. Naming a variant in an arm the modulus cannot select
    // is the same defect wearing a disguise.
    let modulus = target
        .split("let call = match op % ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.trim_end_matches('{').trim().parse::<usize>().ok());
    match modulus {
        Some(n) if n == declared => {}
        Some(n) => {
            eprintln!(
                "hvcall-census: FAIL — {TARGET} selects with `op % {n}` against {declared} \
                 variants. Arms past the modulus are unreachable, so their variants are named but \
                 never generated."
            );
            ok = false;
        }
        None => {
            eprintln!(
                "hvcall-census: FAIL — cannot read the `let call = match op % N` selector in \
                 {TARGET}; the check above would be vacuous without it."
            );
            ok = false;
        }
    }

    if ok {
        eprintln!(
            "hvcall-census: OK — {TARGET} constructs all {declared} HvCall variants, and its \
             selector reaches every one"
        );
    }
    ok
}

/// Every `pub fn NAME(…)` in `text` whose argument list takes `&mut self`.
///
/// Deliberately a small hand parser: `xtask` has **no dependencies** and adding a regex crate to
/// this workspace to read six files would be a poor trade. Generic parameters are skipped before the
/// argument list is scanned, so `pub fn f<T: Fn(u8)>(&mut self)` is read correctly rather than having
/// its bound mistaken for the arguments. A parse that silently stops matching is caught by the
/// caller's `FLOOR`.
fn mutating_ops(text: &str) -> Vec<String> {
    const PAT: &str = "pub fn ";
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(rel) = text[at..].find(PAT) {
        let name_start = at + rel + PAT.len();
        let name_end = name_start
            + text[name_start..]
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap_or(0);
        let name = &text[name_start..name_end];
        at = name_end;
        if name.is_empty() {
            continue;
        }

        // Skip a generic parameter list, so its parentheses are not mistaken for the arguments.
        let mut i = name_end;
        if bytes.get(i) == Some(&b'<') {
            let mut depth = 0usize;
            while i < bytes.len() {
                match bytes[i] {
                    b'<' => depth += 1,
                    b'>' => {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
        }
        if bytes.get(i) != Some(&b'(') {
            continue;
        }

        // The argument list, paren-balanced so a nested `Fn(..)` type cannot end it early.
        let args_start = i;
        let mut depth = 0usize;
        while i < bytes.len() {
            match bytes[i] {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        if i >= bytes.len() {
            continue;
        }
        if text[args_start..i].contains("&mut self") {
            out.push(name.to_string());
        }
        at = i;
    }
    out
}

/// ★ ⑳-l — **`cargo xtask` with no argument must name every task that exists.**
///
/// The usage text is a hand-maintained list of a set the compiler already knows, which is the exact
/// shape the comment above it warns about — *"a number a human retypes is a claim that drifts"*.
/// It had drifted: **`doc-counts`, `doc-paths` and `doc-index` all existed and none was listed**, so
/// the tool's own front door hid three of its gates.
///
/// ⚠ The check is **task ⇒ listed**, not the reverse: the usage text may describe a task in more
/// words than its name, and demanding an exact rendering would make this a formatting gate.
fn help_covers_tasks() -> bool {
    eprintln!("$ xtask help-covers-tasks");

    let Ok(me) = std::fs::read_to_string("xtask/src/main.rs") else {
        eprintln!("help-covers-tasks: cannot read xtask/src/main.rs");
        return false;
    };
    let Some(usage) = me.find("usage: cargo xtask <task>") else {
        eprintln!("help-covers-tasks: FAIL — the usage text is gone; this gate measures nothing.");
        return false;
    };
    let Some(usage_region) = me.find("let ok = match task") else {
        eprintln!("help-covers-tasks: FAIL — the dispatch `match` is gone; nothing to enumerate.");
        return false;
    };
    let help = &me[usage..me[usage..].find(");").map_or(me.len(), |e| usage + e)];

    // The dispatch arms, read from the dispatch `match` ITSELF — bounded to that region rather
    // than scanned file-wide, so a string arm in some other `match` cannot masquerade as a task.
    //
    // ⚠⚠ **The first version required the arm body to contain `(`, and that silently dropped every
    // BLOCK-BODIED arm** — `ci`, `qemu` and `qemu-linux-test`, which are `=> {`. It collected 16 of
    // 19 and reported "all 16 tasks", so the gate ensuring the help names every task **could not
    // see the three that matter most, `ci` among them**. An extraction that under-collects reports
    // success over a smaller universe; that is #275's failure in its partial form, and a floor does
    // not catch it because 16 clears any floor.
    let region = me[usage_region..].split("_ =>").next().unwrap_or("");
    let mut tasks: Vec<&str> = Vec::new();
    for line in region.lines() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix('"') else {
            continue;
        };
        let Some(end) = rest.find('"') else { continue };
        if rest[end + 1..].trim_start().starts_with("=>") && !rest[..end].is_empty() {
            tasks.push(&rest[..end]);
        }
    }
    tasks.sort_unstable();
    tasks.dedup();

    // ⚠⚠ THE FLOOR — #275 again. No arms parsed => nothing to check => vacuously green.
    const MIN_TASKS: usize = 18;
    if tasks.len() < MIN_TASKS {
        eprintln!(
            "help-covers-tasks: FAIL — only {} dispatch arms parsed, expected at least {MIN_TASKS}.",
            tasks.len()
        );
        return false;
    }

    // ⚠⚠ **A task is LISTED only if it BEGINS a help line.** Two weaker rules were tried and both
    // passed a deleted entry:
    //   * `help.contains(t)` — `doc` is a substring of `doc-markers`, `qemu` of `qemu-test`.
    //   * `help.contains(" {t} ")` — space-bounding still passed, because `doc-markers`' own
    //     DESCRIPTION reads "assert every boot marker **a doc QUOTES** is still one the gates
    //     check". A short task name that is also an English word appears in prose, so no
    //     substring rule can work; the structure has to be used instead.
    // ★ The first of those two is the collision `doc_modules` needed a leading `/` for, written
    // again twenty lines later in the same commit. Fixing an instance is not learning the class.
    let listed: Vec<&str> = help.lines().map(str::trim_start).collect();
    let mut ok = true;
    for t in &tasks {
        if !listed.iter().any(|l| l.starts_with(&format!("{t} "))) {
            eprintln!(
                "help-covers-tasks: FAIL — `cargo xtask {t}` exists but the usage text never"
            );
            eprintln!("                   names it. A tool whose help hides its own gates.");
            ok = false;
        }
    }
    if ok {
        eprintln!(
            "help-covers-tasks: OK — the usage text names all {} tasks",
            tasks.len()
        );
    }
    ok
}

/// ★ ⑳-i — **`docs/README.md` must CLASSIFY every document in `docs/`, exactly once.**
///
/// The index is a **corpus claim** — "these are the documents, and this is what each is for" — and
/// this project has learned six times that a corpus claim maintained by memory is a corpus claim
/// that is wrong. So it gets the same treatment as the other six: a **universe check** (#243). The
/// universe is `std::fs::read_dir("docs")`, enumerated independently of the index; the table is the
/// index. A document that exists and is not classified is the failure this exists to catch — a
/// reader who opens `docs/` sees an alphabetical directory listing and no order, and the whole value
/// of the index is that the set it describes is *complete*.
///
/// ## Why "classified", and not merely "mentioned"
///
/// A doc can be linked from the index's prose (the reading orders link seven of them) without ever
/// being placed in a group. That is exactly the half-indexed state this is meant to prevent, so the
/// check reads only **classification rows** — a table line that *begins* with the link, `| [`.
/// Cross-references in prose and in the filename-trap table are ignored on purpose: they start with
/// text, not a link. ⚠ That is a syntactic rule doing semantic work, and it is stated here because a
/// later editor reformatting a table would silently change what this gate measures.
///
/// ⚠ **`docs/README.md` itself is excluded from the universe** — an index that must index itself is
/// a fixed point, not a check.
///
/// ## ⛔ What it does NOT catch, stated rather than glossed
///
/// **A document classified under the WRONG group, or described wrongly.** This checks *set
/// membership*, which is the part that rots mechanically (a doc is added and nobody remembers the
/// index); it cannot check *meaning*, which is the part that needs the diff read. ⚠ Do not let a
/// green `doc-index` be read as "the index is correct" — it says the index is **complete**.
///
/// Six kill-probes, all failing correctly and each naming the right guard (#266): an unindexed new
/// doc · a doc classified twice · a phantom entry · a broken universe enumeration (the floor, and
/// the *asymmetric* direction — a broken row rule fails loudly, a broken enumeration would have
/// passed on nothing) · a doc linked from the reading orders but never grouped, which is the
/// half-indexed state and confirms the prose/table distinction above is real · and a **rename**,
/// where both halves speak and the pair of messages says "moved" rather than leaving it to be
/// inferred.
fn doc_index() -> bool {
    eprintln!("$ xtask doc-index");
    const INDEX: &str = "docs/README.md";

    let mut universe: Vec<String> = match std::fs::read_dir("docs") {
        Ok(d) => d
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.ends_with(".md") && n != "README.md")
            .collect(),
        Err(e) => {
            eprintln!("doc-index: cannot list docs/: {e}");
            return false;
        }
    };
    universe.sort();

    let Ok(index) = std::fs::read_to_string(INDEX) else {
        eprintln!(
            "doc-index: FAIL — {INDEX} is missing. It is the entry point to {} documents; a",
            universe.len()
        );
        eprintln!(
            "           `docs/` directory without one is {} filenames and no reading order.",
            universe.len()
        );
        return false;
    };

    // Classification rows only: a table line whose FIRST cell is the link itself.
    let mut classified: Vec<String> = Vec::new();
    for line in index.lines() {
        let t = line.trim();
        if !t.starts_with("| [") {
            continue;
        }
        let Some(open) = t.find("](") else { continue };
        let Some(close) = t[open + 2..].find(')') else {
            continue;
        };
        classified.push(t[open + 2..open + 2 + close].to_string());
    }

    // ⚠⚠ THE FLOOR — design-lesson #275, and the FOURTH application. With the row rule broken (a
    // reformatted table, a changed link style) `classified` empties, every doc reads as missing and
    // the failure is loud — but the SYMMETRIC break, where the universe fails to enumerate, would
    // report "0 of 0 classified" and pass. Pin the universe, not just the table.
    const MIN_DOCS: usize = 30;
    if universe.len() < MIN_DOCS {
        eprintln!(
            "doc-index: FAIL — only {} documents found in docs/, expected at least {MIN_DOCS}. \
             The enumeration has probably broken, which would make the comparison below vacuous.",
            universe.len()
        );
        return false;
    }

    // ★ The index STATES its own size, and that number is gated rather than deleted (#276). A
    // reader deciding whether to open `docs/` is entitled to know how big it is; the fate that
    // makes that safe is a check, not a promise. ⚠ I wrote this count as prose FIRST —
    // "Thirty-three design documents" — in the rung whose own lesson is that a number is gated,
    // deleted, or rotting. Writing the lesson down is not the same as applying it.
    //
    // ⚠ The phrase is "documents", NOT "design documents", since ⑳-k: `MILESTONES.md` is a LOG, and
    // a count that silently reclassifies a log as a design doc is the small untruth this gate exists
    // to prevent. (The quotation above keeps the ORIGINAL wording — it is a record of what was
    // written, and editing a quote to match today is how a ledger stops being one.)
    let claim = format!("**{} documents.**", universe.len());
    let mut ok = index.contains(&claim);
    if !ok {
        eprintln!("doc-index: FAIL — {INDEX} does not open by stating its own size as `{claim}`;");
        eprintln!(
            "                  docs/ holds {} documents. Update the sentence.",
            universe.len()
        );
    }
    for doc in &universe {
        match classified.iter().filter(|c| *c == doc).count() {
            1 => {}
            0 => {
                eprintln!("doc-index: FAIL — docs/{doc} exists but {INDEX} does not classify it.");
                eprintln!("                  Add it to the group it belongs to (a prose mention is not enough).");
                ok = false;
            }
            n => {
                eprintln!("doc-index: FAIL — docs/{doc} is classified {n} times in {INDEX};");
                eprintln!("                  a document belongs to exactly one group.");
                ok = false;
            }
        }
    }
    for c in &classified {
        if !universe.contains(c) {
            eprintln!(
                "doc-index: FAIL — {INDEX} classifies `{c}`, which is not a document in docs/."
            );
            ok = false;
        }
    }

    if ok {
        eprintln!(
            "doc-index: OK — all {} documents in docs/ are classified exactly once",
            universe.len()
        );
    }
    ok
}

/// Non-comment, non-blank lines under `paths` — the measure the README's proof-to-code ratio uses.
///
/// "Non-comment" means the line, trimmed, does not begin `//` (which covers `///` and `//!`).
/// Block comments are not stripped: the crates counted here use line comments throughout, and a
/// stripper that half-works would be worse than one whose rule is stated. ⚠ The absolute numbers are
/// NOT gated for the reason [`doc_counts`] gives about lines of code — only the RATIO is, because
/// that is the claim.
fn noncomment_lines(paths: &[&str]) -> usize {
    fn walk(dir: &std::path::Path, total: &mut usize) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().is_some_and(|n| n == "target") {
                    continue;
                }
                walk(&p, total);
            } else if p.extension().is_some_and(|x| x == "rs") {
                if let Ok(t) = std::fs::read_to_string(&p) {
                    *total += t
                        .lines()
                        .filter(|l| {
                            let t = l.trim();
                            !t.is_empty() && !t.starts_with("//")
                        })
                        .count();
                }
            }
        }
    }
    let mut total = 0;
    for p in paths {
        walk(std::path::Path::new(p), &mut total);
    }
    total
}

/// ★★ ⑳-g — **THE SIXTH CORPUS: the counts the README STATES about the other five.**
///
/// ⑳ pinned the Kani harnesses, ⑳-b the Verus obligations, ⑳-c the deep sweeps, ⑳-d the boot
/// markers, ⑳-f the lint configs. Each is a body of evidence with something that fails when the SET
/// changes. **This pins the numbers the front door quotes about them** — which nothing checked.
///
/// ⚠ **What it found on its first run, and the pattern is the point.** `README.md` stated the Kani
/// total **twice, differently** — `**113 Kani**` in the evidence-tier table and `(134)` in the crate
/// table — against a real **136**. In the same file Verus was stated twice and was **right both
/// times**. ★ The difference is not care: **Verus's number had not moved and Kani's had.** With
/// nothing checking, correctness is a function of whether the underlying number happened to stay
/// still, which is not a property to rely on.
///
/// ★ This is `xtask`'s own rule about `METAL_LINT_CONFIGS.len()` applied to prose: *a number a human
/// retypes is a claim that drifts; a number derived from the list it describes cannot.* A README
/// cannot interpolate, so the next best thing is to make a wrong one **fail a gate**.
///
/// ## What it deliberately does NOT check
///
/// **Lines of code.** The crate table carried them and they were wrong by up to **12×**
/// (`fvp-probe` stated at 214 against 2 556). They are **deleted, not gated** — per design-lesson
/// #230 a claim in prose that nothing checks is removed rather than corrected, and a gate on line
/// counts would fire on every PR that adds code: a gate with no signal, which trains people to bump
/// a number to make CI green.
///
/// **Per-doc counts** like `docs/SMMU-DEVICE-PATH-COMPOSITION.md`'s "59 harnesses" are claims about a
/// SUBSET, so they are outside this check by construction — named here because a reader grepping for
/// `harnesses` will find them and wonder.
///
/// ⚠⚠ **THE BOOT MARKERS, and the reason is a bug this function had on its first run.** It summed
/// [`MARKER_CORPUS`]'s arrays to **113** and called that "the boot-marker corpus" — but
/// [`doc_markers`] reports **214**, because the corpus is those arrays PLUS `boot-test.sh`'s 177
/// lines, deduplicated. Three defensible numbers (113 array entries · 177 script lines · 214 deduped
/// distinct), and I picked one and labelled it the total. ★ **A SUBSET presented as a TOTAL, in the
/// gate written to stop exactly that** (#155). Markers are excluded rather than checked against a
/// number I would have to choose; [`doc_markers`] already polices the marker TEXT, which is the half
/// that silently rots.
fn doc_counts() -> bool {
    eprintln!("$ xtask doc-counts");

    let readme = match std::fs::read_to_string("README.md") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("doc-counts: cannot read README.md: {e}");
            return false;
        }
    };

    // Each entry is the phrase the README must contain — matched LITERALLY and INCLUDING the number,
    // so a drifted count simply is not found. Same shape `doc_markers` uses for quoted boot markers.
    let verus_total: u32 = VERUS_OBLIGATIONS.iter().map(|(_, n)| n).sum();
    let claims: &[(String, &str)] = &[
        (
            format!("**{} Kani**", KANI_HARNESSES.len()),
            "the Kani harness corpus",
        ),
        (
            format!("**{verus_total} Verus**"),
            "the Verus obligation corpus",
        ),
        (
            format!("the **Kani harnesses** ({})", KANI_HARNESSES.len()),
            "the crate table's Kani count",
        ),
        (
            format!("({verus_total} obligations)"),
            "the crate table's Verus count",
        ),
        (
            format!("**{}** deep exhaustive sweeps", DEEP_SWEEPS.len()),
            "the deep-sweep corpus",
        ),
    ];

    // ★ THE PROOF-TO-CODE RATIO — the README's headline comparison against seL4, and the one number
    // in this file that answers the question the whole project poses ("how much assurance for what
    // fraction of a full-verification budget"). It is checked to TWO DECIMAL PLACES, which is the
    // right precision for two reasons found by measuring: the components drift constantly (+178
    // proof / +150 code since the figure was written) while the ratio did **not move at all**, so an
    // exact-component gate would fire on every PR for no signal — and a real regression, proof
    // stalling while code grows, moves the second decimal long before anyone would notice by eye.
    let proof = noncomment_lines(&["hv-verify/src", "hv-verify/verus"]);
    let code = noncomment_lines(&["hv-core/src", "hv-s2/src", "hv-vdev/src", "hv-part/src"]);
    #[allow(clippy::cast_precision_loss)] // line counts are far below f64's exact-integer range
    let ratio = proof as f64 / code as f64;
    let ratio_phrase = format!("**{ratio:.2}:1**");
    let mut ok = readme.contains(ratio_phrase.as_str());
    if ok {
        eprintln!("doc-counts: OK   — the proof-to-code ratio: README says `{ratio_phrase}` ({proof} proof / {code} code)");
    } else {
        eprintln!("doc-counts: FAIL — the proof-to-code ratio: measured {ratio:.2}:1 ({proof} non-comment");
        eprintln!(
            "                   lines of proof over {code} of model+emitter), but README.md does"
        );
        eprintln!("                   not contain `{ratio_phrase}`.");
    }

    for (phrase, what) in claims {
        if readme.contains(phrase.as_str()) {
            eprintln!("doc-counts: OK   — {what}: README says `{phrase}`");
        } else {
            eprintln!("doc-counts: FAIL — {what}: README does not contain `{phrase}`.");
            eprintln!("                   Either the count changed and the README did not, or the");
            eprintln!("                   wording moved. Both are the same fix: make them agree.");
            ok = false;
        }
    }
    if ok {
        eprintln!(
            "doc-counts: OK — {} corpus counts + the proof-to-code ratio match the gates",
            claims.len()
        );
    }
    ok
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
const BOOT_TEST_CONFIGS: usize = 7;

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
    // The mixed-criticality boot's 37. ★ **This gate's universe check caught the array the DAY it
    // was written** — the corpus was added, the boot was wired up and verified green, and
    // `doc-markers` still failed with "`LINUX_MONITOR_MARKERS` is a marker array that
    // `MARKER_CORPUS` does not pin, so it is ungated". That is ⑳-d's other half doing exactly what
    // it was built for, on its author, before the PR left the branch.
    ("LINUX_MONITOR_MARKERS", LINUX_MONITOR_MARKERS, 45),
    // ㉗'s forbidden list. Registered here on arrival — ㉖ learned that the hard way when this
    // gate's universe check caught `LINUX_MONITOR_MARKERS` ungated *after* the boot was already
    // green, and a forbidden array is exactly as silent when nothing pins it.
    ("LINUX_MONITOR_FORBIDDEN", LINUX_MONITOR_FORBIDDEN, 1),
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
const BOOT_TEST_MARKERS: usize = 182;

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
    "policy_work_conservation::advance_leaves_no_legal_dispatch_unmade",
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
