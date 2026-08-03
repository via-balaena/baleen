// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # M5 Arc 5e — the real-Linux capstone (feature `real-linux`)
//!
//! The documented drop-in from `docs/ARC-5-M5-GUEST-INTERFACE.md`: boot a **real** aarch64 Linux
//! kernel as a single EL1 guest that "owns the machine", on the interfaces the synthetic Arc 0–5
//! guests already proved sound. **No isolation content** — the thesis (Arcs 0–4) is proven on the
//! un-forgeable synthetic guests; this arc only demonstrates the already-proven hardware interface
//! carries an unmodified kernel. `hv-core`/`hv-hal` are untouched; this whole module is behind the
//! `real-linux` feature, so the default build (the CI boot-test) is byte-for-byte unchanged.
//!
//! ## The model — the guest owns its RAM, and NOTHING else
//!
//! hv-metal maps the guest's RAM window through Stage-2 and **no device MMIO whatsoever**:
//! `stage2::windows().device_len == 0`, which [`crate::vgic`] asserts at compile time. Every device
//! the kernel drives is EL2 state, and its interrupts are EL2's too. That took three rungs, one
//! device at a time — the window shrank 32 MiB → 16 MiB → 0:
//!
//! | rung | what stopped being the machine's | window |
//! |---|---|---|
//! | Arc 5e | — (the guest owned the UART and the GIC) | 32 MiB |
//! | ③-a1 | the **console** — an emulated PL011 ([`crate::vpl011`]) | 16 MiB |
//! | ③-a2 | interrupt **delivery** — `HCR_EL2.IMO=1`, forwarded through list registers | 16 MiB |
//! | ③-b1 | the interrupt **controller** — an emulated GICv3 ([`crate::vgic`]) | **0** |
//!
//! Each shrink was free of `guest.dts` edits, which is the property that makes the guest genuinely
//! unmodified: ③-a1 worked because the GIC redistributor region ends exactly where the PL011 begins
//! on QEMU `virt`, and ③-b1 because the emulated distributor reports a `GICD_TYPER` covering the
//! INTIDs the existing DTB already names.
//!
//! So **four** things reach EL2 now: `HVC` (PSCI — Linux's `method = "hvc"`), an `EC=0x24` Stage-2
//! **data abort**, which [`handle_linux_sync`] routes to the emulated GIC or the emulated PL011 and
//! otherwise reports as a bring-up fault; an `EC=0x18` **trapped system register**
//! ([`handle_linux_sysreg_trap`], the guest's `ICC_SGI1R_EL1` writes); and every **physical IRQ**
//! ([`handle_linux_irq`]).
//!
//! ## ③-a2: the guest's interrupts stop being its own
//!
//! `IMO=1` is not a free addition; it **takes away something that worked**. Under `IMO=0` the kernel
//! took its arch-timer PPI (INTID 27) directly, and that is what drove its scheduler. Routing it to
//! EL2 makes hv-metal responsible for giving it back, and a guest that does not get its tick does not
//! boot — so the timer, not the UART, is the load-bearing half of this rung.
//!
//! **The mechanism is `ICH_LR<n>_EL2.HW`, and the synthetic path's answer does not carry over.**
//! `guest.rs` answers the timer PPI with `gic::disable_vtimer()` — a one-shot, which is all a
//! synthetic guest wants and is fatal to a kernel that needs a periodic tick. The arch timer's PPI is
//! **level-triggered**, so it stays asserted until the guest reprograms `CNTV_CVAL_EL0`; EL2 must
//! therefore leave the physical interrupt Active until the guest has done so, and EL2 has no way to
//! know when that is. A hardware-mapped list register makes the guest's own EOI deactivate the
//! physical interrupt (`gic::inject_hw`, with `ICC_CTLR_EL1.EOImode=1` at EL2 so EL2's own EOI drops
//! priority without deactivating). This is how KVM forwards the arch timer.
//!
//! **③-a2 left the GICD/GICR pass-through and ③-b1 closed that** — see [`crate::vgic`], which also
//! carries the mediation seam this file now consults before forwarding ([`handle_linux_irq`]).
//! The emulated UART is still transmit-only: its RX path needs a forwarded SPI, which ③-a2's
//! machinery supports but nothing yet wires (see [`crate::vpl011`]'s module docs).
//!
//! ## ③-b2b-ii-a: everything per-guest becomes an INDEX
//!
//! Each device above is EL2 state, which is what makes a *second* copy of it possible. That
//! possibility is now taken: the emulated PL011s, the emulated GICv3s, the vCPU contexts and the
//! five witness counters are arrays indexed by [`CURRENT`], and a guest's domain id, Stage-2 set,
//! frame range and table range are all functions of its slot. Only slot A runs — moving `CURRENT`
//! is ③-b2b-ii-c, and what stands in its way is not this file but the **physical** timer's Active
//! state, measured rather than assumed: at every preemption point PPI 27 is Active *and* Pending
//! with the running guest holding the `HW=1` list register that owns its deactivation, so a second
//! guest switched in there could never be signalled the tick — and the tick is the only thing that
//! re-enters EL2.
//!
//! The **console** had to move with them ([`crate::console`]). ③-a1's relay is per-byte, and the
//! preemption point can land between any two bytes of a line, so two kernels would interleave
//! character by character — and `xtask::LINUX_MARKERS` is substring matching over that log. EL2
//! therefore buffers each guest's stream to a newline and tags the line with the model instance that
//! received it, which is also the only attribution a guest cannot forge: both guests run the *same*
//! initramfs.
//!
//! ## The memory contract (shared with `cargo xtask qemu-linux`)
//!
//! QEMU `-device loader` deposits three blobs in guest DRAM before hv-metal runs; hv-metal never
//! copies them — it just points the kernel's boot registers at them. hv-metal owns the low 128 MiB
//! (its image is at `0x4008_0000`); the guest owns `0x4800_0000 .. 0x8000_0000` (needs `-m 1024`).
//!
//! | blob      | guest PA      | how the kernel finds it            |
//! |-----------|---------------|------------------------------------|
//! | `Image`   | `0x4800_0000` | `ELR_EL2` (entry, arm64 boot proto)|
//! | DTB       | `0x4b00_0000` | `x0`                               |
//! | initramfs | `0x4c00_0000` | DTB `/chosen` `linux,initrd-*`     |
//!
//! ## Unsafe
//!
//! As the rest of the metal: EL2 system-register setup, the vector-table `global_asm!`, and the
//! `eret` handoff. Every block carries its justification. The Stage-2 table **writes** are no longer
//! among them — since M5 Arc 4 the tables live in a [`crate::cell::BootCell`] (never `static mut`,
//! and no longer a bare `UnsafeCell` either), so building them is ordinary safe code and their
//! exclusivity is checked rather than commented; the same discipline as `stage2.rs`/`guest.rs`.

use core::arch::{asm, global_asm};
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use hv_core::hypervisor::DomId;
use hv_core::p2m::{Mfn, PtLevel};
use hv_core::{HvCall, Hypervisor};

use crate::abort::{self, DataAbort, EC_DATA_ABORT};
use crate::cell::BootCell;
use crate::console::GuestConsole;
use crate::gic;
use crate::pl011::Pl011;
use crate::stage2::{self, HCR_EL2_VM, VTCR_EL2};
use crate::vcpu;
use crate::vgic::{self, DeployedGic};
use crate::vpl011::{self, DeployedPl011};

/// The control domain.
const DOM0: DomId = 0;

/// How many real-Linux guests this build carries.
///
/// **③-b2b-ii-a turned "A and B" from two hand-written cases into an index**, because every piece of
/// per-guest state below — device models, vCPU context, witness counters, console buffers — needed
/// to become two of itself at once, and four independent A/B pairs is four chances for one of them
/// to be forgotten. What the arc is really doing is making "which guest" a *value* rather than a
/// place in the source.
pub(crate) const NUM_GUESTS: usize = 2;

/// The guest slot that boots first, and the one that does not run until ③-b2b-ii-c.
const SLOT_A: usize = 0;
const SLOT_B: usize = 1;

/// A guest slot's model [`DomId`]. Dom 0 is the control domain, so guest slot `i` is dom `i + 1`.
///
/// One derivation for the whole file: the domain id, the Stage-2 set, the frame range and the table
/// range are all functions of the slot, so a third guest would be a change to [`NUM_GUESTS`] and
/// nothing else. (`pub(crate)` for [`crate::console`], which tags each guest's console lines and
/// must name the same domain this file dispatches to.)
pub(crate) const fn slot_dom(slot: usize) -> DomId {
    slot as DomId + 1
}

/// The domain the first real Linux kernel boots as.
const GUEST_A: DomId = slot_dom(SLOT_A);
/// The PEER domain (③-b2a). It owns the second half of the guest-RAM window and has a fully emitted
/// Stage-2 image, but does not execute — running it is ③-b2b-ii-c. ③-b2b-i built the switch this
/// path was missing and proved it carries a *real* kernel's state; ③-b2b-ii-a gave B its own device
/// models, vCPU context and console; what remains is B's own blobs and the live negative test. What
/// B exists for here is to make the existing negative test meaningful: see [`run`].
const GUEST_B: DomId = slot_dom(SLOT_B);

/// A guest's Stage-2 table set **is** its slot.
///
/// Not a coincidence to be maintained by hand: the emitter holds [`stage2::NUM_STAGE2_SETS`]
/// independent sets, each tagged with its own VMID, and one guest needs exactly one. Binding the two
/// indices makes "guest B's image" and "set 1" the same statement, and puts the capacity question
/// where the compiler can answer it.
const _: () = assert!(
    NUM_GUESTS <= stage2::NUM_STAGE2_SETS,
    "each real-Linux guest needs its own VMID-tagged Stage-2 set"
);

/// The first super-span model frame guest `slot` owns. **This is the isolation mechanism** — the two
/// guests are disjoint because neither ever names the other's frames (see [`build_model_and_stage2`]).
const fn first_frame(slot: usize) -> Mfn {
    (slot as u64 * stage2::LINUX_SUP_FRAMES_PER_GUEST) as Mfn
}

/// The first model frame holding an `L2` page table for guest `slot` — just above the super
/// partition, in the base partition, and never mapped (a page table is model state, not a leaf).
/// Each domain gets its own contiguous run of `LINUX_TABLES_PER_GUEST`.
const fn first_table(slot: usize) -> Mfn {
    stage2::NUM_SUP_FRAMES as Mfn + (slot as u64 * stage2::LINUX_TABLES_PER_GUEST) as Mfn
}

/// The running guest's single vCPU, and the physical CPU it is dispatched onto (③-b2b-i). One of
/// each: the machine is single-CPU throughout, and a vCPU id is scoped to its domain in
/// `hv_core::sched`, so both guests' vCPU 0 are different vCPUs.
const LINUX_VCPU: u32 = 0;
const PCPU0: u32 = 0;

/// **Which guest slot is executing.** ③-b2b-ii-a's seam: every handler below indexes its per-guest
/// state through this rather than through a constant, and ③-b2b-ii-c is the rung that makes it move.
///
/// Deliberately an atomic rather than a `const`, and that is load-bearing for the *witness*, not
/// only for the future: an array indexed by a constant is one the compiler can fold back into a
/// global, which would make this rung's refactor indistinguishable from its absence. The per-guest
/// report ([`report_per_guest_state`]) is the other half of that argument.
///
/// Plain atomic, not a [`BootCell`]: written from EL2 exception handlers, which is `crate::cell`'s
/// class-3 hazard. An atomic has no borrow to overlap — the same reasoning [`TIMER_FORWARDED`] and
/// `guest.rs`'s `VCPU_PENDING` record.
static CURRENT: AtomicUsize = AtomicUsize::new(SLOT_A);

/// The guest slot currently executing at EL1.
fn current_slot() -> usize {
    CURRENT.load(Ordering::Relaxed)
}

// ─── the memory contract ─────────────────────────────────────────────────────────────────────────
//
// FOUR places have to agree about where guest RAM is: the emitter's window, this file, the DTB's
// `/memory` node, and xtask's `-device loader` addresses. Three of them are now ONE declaration —
// `crate::stage2::LINUX_RAM_BASE`/`LINUX_RAM_END`, which is what `build_stage2_from_p2m` actually
// maps. This file used to keep its own `GUEST_RAM_BASE`/`GUEST_RAM_END` literals, and by the time ⑭
// found them they reached nothing but a `writeln!` — a value in a diagnostic and in no boolean, the
// shape design-lesson #74 names.
//
// The FOURTH — xtask's loader addresses — is in a crate that cannot depend on `hv-metal` (this crate
// is workspace-excluded; it does not link for the host), so it CANNOT be folded in at compile time.
// It is bound at RUN time instead: the banner below prints these addresses, and
// `xtask::LINUX_MARKERS` asserts that whole line, so the gate fails if this file and xtask disagree.
// See `docs/ARC-5-M5-GUEST-INTERFACE.md` §5f.

use crate::stage2::{LINUX_RAM_BASE as GUEST_RAM_BASE, LINUX_RAM_END as GUEST_RAM_END};

/// Kernel `Image` load address — the base of guest RAM, per the arm64 boot protocol. `ELR_EL2` entry.
const KERNEL_ENTRY: u64 = GUEST_RAM_BASE;
/// Flattened device tree (DTB) load address — handed to the kernel in `x0`. The one address here
/// with no authoritative source under the fence: it names a spot inside guest RAM that xtask's
/// `-device loader` writes to, so it is asserted at run time (see the note above) rather than
/// derived.
const DTB_ADDR: u64 = 0x4b00_0000;

/// The kernel and the DTB must land inside the RUNNING guest's half of the window (③-b2a).
///
/// `KERNEL_ENTRY` is `LINUX_RAM_BASE` by derivation so it is safe by construction, but `DTB_ADDR` is
/// a bare literal — the one address here with no authoritative source under the fence. Before the
/// split it only had to be inside a 896 MiB window and could not plausibly fall out; now it has to
/// be inside a 448 MiB one, and a further split would put it in the PEER's half, where the kernel
/// would be handed a pointer its own Stage-2 cannot translate. That failure looks like a kernel that
/// dies before its first console byte, with nothing naming the cause. True or the build fails (#97).
const _: () = assert!(
    KERNEL_ENTRY >= stage2::LINUX_RAM_BASE && KERNEL_ENTRY < stage2::LINUX_RAM_SPLIT,
    "the kernel image must load inside the running guest's half of the window"
);
const _: () = assert!(
    DTB_ADDR >= stage2::LINUX_RAM_BASE && DTB_ADDR < stage2::LINUX_RAM_SPLIT,
    "the DTB must load inside the running guest's half of the window — a DTB in the peer's half is \
     a pointer the guest's Stage-2 cannot translate"
);

// The Stage-2 descriptor encodings, the device window and the translation regime used to be declared
// HERE, alongside a 40-line identity mapper. M5 Arc 6b deleted the mapper and moved the emission to
// `crate::stage2` — but only the mapper actually went: TEN constants (`DEV_BASE`, `DEV_END`,
// `DESC_TABLE`, `DESC_BLOCK`, `ADDR_2M`, `ADDR_4K`, `LEAF_AF_RW`, `BLOCK_NORMAL_RWX`,
// `BLOCK_DEVICE`, `GUEST_VMID`) outlived their last use, under a comment claiming they were gone.
// Nothing could catch that: `main.rs` carried a CRATE-WIDE `allow(dead_code)` for `real-linux`, the
// only configuration that compiles this file, so this was the one module no build ever linted for
// dead code (⑭). They are gone now, and the allow is per-item.
//
// The device window is `crate::stage2::windows().device_base`/`device_len`; the leaf attributes are
// `hv_s2`'s emit seams; `VTCR_EL2`/`HCR_EL2_VM` are `crate::stage2`'s.

/// `SPSR_EL2` to `eret` into the kernel: EL1h (`M[3:0]=0b0101`, uses `SP_EL1`), AArch64, `DAIF`
/// masked — the arm64 boot protocol enters with interrupts off; the kernel unmasks them itself.
const SPSR_EL2_LINUX: u64 = 0b0101 | (0b1111 << 6);

/// `SCTLR_EL1` enables the kernel must be entered with CLEAR (arm64 boot protocol: MMU off, D-cache
/// off): `M` (0), `A` (1), `C` (2), `SA` (3), `SA0` (4), `I` (12).
const SCTLR_EL1_ENABLES: u64 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 12);

// ─── Stage-2 tables ──────────────────────────────────────────────────────────────────────────────

// The Stage-2 tables live in `crate::stage2` now — the same storage the proven emitter uses for the
// synthetic guests. This file used to declare its own, alongside its own descriptor encodings and
// its own 40-line identity mapper; all three are gone (M5 Arc 6b). That duplication WAS the gap:
// the only real guest ran behind an emitter no proof touched.

/// Build this guest's model in `hv-core`, then emit its Stage-2 through the **proven emitter**.
///
/// **This is what M5 Arc 6b is for.** Until now the only real guest ran behind `build_stage2` — forty
/// lines of hand-rolled identity mapping in this file that no proof touched — while the emitter with
/// the ∀-N refinement theorem behind it could only address 2 MiB and so could not host a kernel. Arc
/// 6a gave that emitter superpages; this makes the kernel use it.
///
/// The model: `guest` owns `LINUX_TABLES_PER_GUEST` `L2`-pinned page tables, with one **leaf edge
/// per 2 MiB** of its half of the window, starting at model frame `first_frame`. A leaf out of an
/// `L2` table is a superpage (`hv_s2::Span::Super`), so the emitter writes 2 MiB blocks — and
/// because the super window's IPA and PA bases are both `LINUX_RAM_BASE`, the mapping is identity,
/// as the arm64 boot protocol and the DTB's `/memory` node require.
///
/// **③-b2a made this per-domain.** It used to hard-code one domain, one set and the whole window;
/// now the domain, its frame range, its table range and its Stage-2 set are all parameters, which is
/// what lets [`run`] build a peer with a real image of its own.
///
/// **There is no device pass-through window to describe any more** — this doc used to explain how
/// the emitter maps one as infrastructure, which stopped being true at ③-b1 when the GIC became
/// EL2 state and `windows().device_len` went to zero (`crate::vgic` asserts it at compile time).
fn build_model_and_stage2(
    hv: &mut Hypervisor,
    uart: &mut Pl011,
    guest: DomId,
    first_frame: Mfn,
    first_table: Mfn,
    set: usize,
) -> u64 {
    let mut go = |caller: DomId, call: HvCall, what: &str| {
        if let Err(e) = crate::teardown::dispatch(hv, caller, call) {
            let _ = writeln!(
                uart,
                "baleen: linux model setup '{what}' failed for dom {guest}: {e:?}; halting"
            );
            crate::park();
        }
    };

    go(
        DOM0,
        HvCall::DomainCreate {
            target: guest,
            may_create: false,
        },
        "create the linux domain",
    );

    // One super-span leaf per 2 MiB of THIS guest's half of the window, spread across
    // `LINUX_TABLES_PER_GUEST` `L2`-pinned tables because `hv_core::TABLE_SLOTS` is 8 (see
    // `crate::NUM_FRAMES`). Each table is allocated and pinned before its leaves are linked.
    //
    // **③-b2a: the frame range is a PARAMETER, and that is the whole isolation mechanism.** The two
    // guests are disjoint because each links a different half of the frame space — not because of a
    // check somewhere, but because neither ever names the other's frames. `hv-core` then refuses any
    // later attempt to (a frame is owned by at most one domain), and the emitter maps exactly the
    // leaves it finds, so the Stage-2 images inherit the disjointness rather than re-deriving it.
    for t in 0..stage2::LINUX_TABLES_PER_GUEST {
        let table = first_table + t as Mfn;
        go(
            guest,
            HvCall::P2mAllocate { mfn: table },
            "allocate a table",
        );
        go(
            guest,
            HvCall::P2mPin {
                mfn: table,
                level: PtLevel::L2,
            },
            "pin a table at L2",
        );
        for slot in 0..hv_core::p2m::TABLE_SLOTS {
            let offset = t * hv_core::p2m::TABLE_SLOTS as u64 + slot as u64;
            if offset >= stage2::LINUX_SUP_FRAMES_PER_GUEST {
                break;
            }
            let m = first_frame + offset as Mfn;
            go(
                guest,
                HvCall::P2mAllocate { mfn: m },
                "allocate a RAM frame",
            );
            go(
                guest,
                HvCall::P2mLink {
                    parent: table,
                    slot,
                    child: m,
                    writable: true,
                    leaf: true,
                    execute: false,
                },
                "link a RAM superpage",
            );
        }
    }

    let base = stage2::LINUX_RAM_BASE + first_frame as u64 * stage2::SUP_FRAME_BYTES;
    let _ = writeln!(
        uart,
        "baleen: linux model built for dom {guest} — {} super-span leaves ({} MiB at \
         0x{base:08x}) across {} L2-pinned tables, into stage-2 set {set}",
        stage2::LINUX_SUP_FRAMES_PER_GUEST,
        stage2::LINUX_SUP_FRAMES_PER_GUEST * stage2::SUP_FRAME_BYTES / (1024 * 1024),
        stage2::LINUX_TABLES_PER_GUEST
    );

    stage2::build_stage2_from_p2m(hv, guest, set)
}

/// **③-b2a's proven half: walk BOTH emitted images and assert each reaches exactly its own frames
/// and nothing of the peer's**, over every frame of the guest-RAM window, plus three probes that
/// neither image maps anything outside it.
///
/// **Why a walk and not layout arithmetic.** Computing "what A should reach" from the same constants
/// the emitter used would make a wrong emission and a wrong expectation agree — design-lesson #36,
/// and the reason `walk_stage2` exists at all. This reads the descriptor bytes the hardware itself
/// walks, so the check is a second, independent reading of what was actually written. Because the
/// super window's IPA and PA bases are equal, `reach.pa == ipa` checks the identity property and the
/// destination in one comparison.
///
/// **What it is NOT — and the citation is stated precisely, because compressing it is the failure
/// this project watches for.** This is a boot-time check on two concrete images, not a theorem;
/// `hv-metal` is not a Kani target. What `hv-verify` proves, and at which quantifier:
/// * `emitted_leaf_map_is_always_authorized` — ∀ edge set / target domain / table capacity, the
///   emitted map is authorized frame by frame, or fails loudly. Not ∀-address.
/// * `an_unauthorized_frame_is_never_mapped` — the isolation corollary in its negative form: a frame
///   a domain neither owns nor holds a grant for is **not in the table at all**. Also ∀-frame.
/// * `the_walk_lands_where_the_windows_say` — ∀ *address*, but on one **fixture** `Layout`, not
///   ∀-layout.
///
/// So the proofs cover the *relation* ∀-frame and the *walk* ∀-address-on-a-fixture; this check is
/// what ties them to the two `Layout`s actually deployed. **What is new is that one of the two
/// domains is a real Linux kernel** — the part the synthetic Arc-2 pair could not say.
fn report_disjointness(vttbr: &[u64; NUM_GUESTS], uart: &mut Pl011) {
    // The report below is written PAIRWISE — "dom 1 reaches 0 of dom 2's" — and a third guest would
    // make that sentence false rather than incomplete. Everything else in this file is a function of
    // the slot; this one place is not, so the precondition is a compile-time fact instead of an
    // unstated assumption (design-lesson #97).
    const _: () = assert!(
        NUM_GUESTS == 2,
        "the disjointness report is written for exactly two guests"
    );

    let l1_a = hv_s2::arm64::vttbr_table(vttbr[SLOT_A]);
    let l1_b = hv_s2::arm64::vttbr_table(vttbr[SLOT_B]);
    if l1_a == l1_b {
        let _ = writeln!(
            uart,
            "baleen: peer FAIL: both domains were emitted into ONE table set — there is no second \
             image to be isolated from"
        );
        crate::park();
    }

    let per = stage2::LINUX_SUP_FRAMES_PER_GUEST;
    let (mut a_own, mut b_own, mut a_peer, mut b_peer) = (0u64, 0u64, 0u64, 0u64);

    for m in 0..stage2::NUM_SUP_FRAMES {
        let ipa = stage2::LINUX_RAM_BASE + m * stage2::SUP_FRAME_BYTES;
        let mine_is_a = m < per;
        let ra = stage2::walk_stage2(l1_a, ipa);
        let rb = stage2::walk_stage2(l1_b, ipa);

        // The identity property the arm64 boot protocol needs, checked from the DESCRIPTORS: an
        // owned frame must resolve to its own IPA, not merely to something.
        for (r, owns, own_count, peer_count) in [
            (ra, mine_is_a, &mut a_own, &mut a_peer),
            (rb, !mine_is_a, &mut b_own, &mut b_peer),
        ] {
            match (r, owns) {
                (Some(reach), true) if reach.pa == ipa => *own_count += 1,
                (None, false) => {}
                // The isolation failure: a PEER's frame that resolved at all. Counted rather than
                // parked on, so the report says how MANY leaked instead of only where the first one
                // was — an image mapping one stray frame and one mapping the peer's whole half are
                // different bugs. The owned-frame failures below park immediately because they mean
                // the image is malformed, and every later reading of it would be noise.
                (Some(_), false) => *peer_count += 1,
                _ => {
                    let _ = writeln!(
                        uart,
                        "baleen: peer FAIL: frame {m} (IPA 0x{ipa:08x}) did not resolve to its own \
                         identity mapping in its owner's image"
                    );
                    crate::park();
                }
            }
        }
    }

    // **Nothing OUTSIDE the guest-RAM window may be mapped by either image.** The loop above only
    // walks the 448 RAM frames, so on its own "DISJOINT" would be a claim about that window and
    // silent about everything else — and the `Layout` has other windows the emitter could populate
    // (`data_ipa_base`, and the synthetic super window a shared constant still names). The address
    // that matters most is the one just BELOW guest RAM: that is hv-metal's own memory, and an image
    // reaching it is a guest reaching the hypervisor, not merely a peer.
    //
    // Three probes, not ∀-address — a boot check cannot be exhaustive, and the ∀ statement is
    // `hv-verify`'s (`the_walk_lands_where_the_windows_say`). What these catch is a LAYOUT change
    // that starts emitting somewhere new, which is the realistic failure.
    let outside: [(u64, &str); 3] = [
        (
            stage2::LINUX_RAM_BASE - stage2::SUP_FRAME_BYTES,
            "hv-metal's own memory",
        ),
        (stage2::DATA_IPA_BASE, "the base-span data window"),
        (stage2::SUP_IPA_BASE, "the synthetic super window"),
    ];
    for (ipa, what) in outside {
        for (l1, dom) in [(l1_a, GUEST_A), (l1_b, GUEST_B)] {
            if stage2::walk_stage2(l1, ipa).is_some() {
                let _ = writeln!(
                    uart,
                    "baleen: peer FAIL: dom {dom}'s image maps 0x{ipa:08x} — {what}, which is \
                     outside the guest-RAM window and must be unmapped in BOTH images"
                );
                crate::park();
            }
        }
    }

    if a_own == per && b_own == per && a_peer == 0 && b_peer == 0 {
        let _ = writeln!(
            uart,
            "baleen: peer OK: two domains, two Stage-2 images, DISJOINT over the guest-RAM window \
             — dom {GUEST_A} reaches its {a_own} frames and 0 of dom {GUEST_B}'s; dom {GUEST_B} \
             reaches its {b_own} and 0 of dom {GUEST_A}'s; and neither maps hv-metal's memory or \
             any window outside guest RAM ({} frames + 3 out-of-window probes, walked from the \
             emitted descriptors)",
            stage2::NUM_SUP_FRAMES
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: peer FAIL: the two images are NOT disjoint — dom {GUEST_A} own={a_own} \
             peer={a_peer}, dom {GUEST_B} own={b_own} peer={b_peer} (expected own={per}, peer=0)"
        );
        crate::park();
    }
}

/// Program + enable Stage-2: write `VTCR_EL2`/`VTTBR_EL2`, set `HCR_EL2.VM`, then TLB-invalidate for
/// the VMID and synchronize. Load-bearing on silicon, invisible under QEMU/TCG.
///
/// `IMO` is deliberately NOT set here — `gic::enable_el2` sets it at the very end of [`run`], after the
/// Linux vector table is installed, because it is the instruction that starts routing physical IRQs to
/// EL2 and they must have somewhere correct to land.
fn enable_stage2(vttbr: u64) {
    // SAFETY: all EL2-legal system registers; `HCR_EL2` read-modify-write adds `VM` while keeping the
    // Arc-3 `RW` bit and leaving `IMO`/`FMO` untouched (③-a2's `gic::enable_el2` adds `IMO` later, by
    // the same read-modify-write discipline). Stage-2 affects only EL1&0, never EL2's own
    // MMU-off/identity accesses.
    unsafe {
        asm!(
            "msr vtcr_el2, {vtcr}",
            "msr vttbr_el2, {vttbr}",
            "mrs {tmp}, hcr_el2",
            "orr {tmp}, {tmp}, {vm}",
            "msr hcr_el2, {tmp}",
            "dsb ish",
            "tlbi vmalls12e1is",
            "dsb ish",
            "isb",
            vtcr = in(reg) VTCR_EL2,
            vttbr = in(reg) vttbr,
            vm = in(reg) HCR_EL2_VM,
            tmp = out(reg) _,
            options(nostack),
        );
    }
}

/// Let the guest (EL1) use the GICv3 system-register CPU interface and the arch timer without
/// trapping to EL2: `ICC_SRE_EL2` = SRE + Enable (so `ICC_SRE_EL1` is accessible), and
/// `CNTHCTL_EL2` = EL1PCTEN|EL1PCEN (no physical counter/timer trap). The kernel drives the real GIC
/// and virtual timer directly; hv-metal does NOT pre-init the physical GIC (Linux does).
fn enable_guest_hw_access() {
    const ICC_SRE_EL2_SRE_EN: u64 = (1 << 0) | (1 << 3);
    const CNTHCTL_EL1_TIMER: u64 = (1 << 0) | (1 << 1);
    // SAFETY: `ICC_SRE_EL2` and `CNTHCTL_EL2` are EL2 control registers; we set only the documented
    // enable bits (read-modify-write for SRE to preserve IMPDEF bits), `isb` before the guest relies
    // on the interface. No memory effect.
    unsafe {
        asm!(
            "mrs {t}, ICC_SRE_EL2",
            "orr {t}, {t}, {sre}",
            "msr ICC_SRE_EL2, {t}",
            "msr CNTHCTL_EL2, {cnt}",
            "isb",
            t = out(reg) _,
            sre = in(reg) ICC_SRE_EL2_SRE_EN,
            cnt = in(reg) CNTHCTL_EL1_TIMER,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Clear the guest's `SCTLR_EL1` enables (MMU/caches off) so the kernel is entered Stage-1-off from a
/// known state, as the arm64 boot protocol requires. RES1 bits are preserved (read-modify-write).
fn init_guest_el1() {
    // SAFETY: `SCTLR_EL1` is writable from EL2; the read-modify-write clears exactly the enable bits
    // and preserves RES1. No memory effect.
    unsafe {
        asm!(
            "mrs {tmp}, sctlr_el1",
            "bic {tmp}, {tmp}, {en}",
            "msr sctlr_el1, {tmp}",
            en = in(reg) SCTLR_EL1_ENABLES,
            tmp = out(reg) _,
            options(nomem, nostack),
        );
    }
}

// ─── the Linux-mode EL2 exception vectors ────────────────────────────────────────────────────────
// A dedicated vector table installed just before the `eret` into Linux — separate from the synthetic
// path's (`exceptions.rs`), so the synthetic code is untouched. Slot 8 (lower-EL sync) → the PSCI /
// abort handler below; every other slot → the diagnostic reporter (`handle_exception`, reused).
// With `IMO=0` the guest's device interrupts go straight to its EL1, so EL2 sees no guest IRQs.

global_asm!(
    r#"
    .section .text
    .balign 0x800
    .global __linux_vectors
__linux_vectors:
    .macro lventry index
    .balign 0x80
    mov     w0, #\index
    b       __linux_diag
    .endm

    lventry 0    // Current EL SP0 — Sync
    lventry 1
    lventry 2
    lventry 3
    lventry 4    // Current EL SPx — Sync (EL2's own faults land here)
    lventry 5
    lventry 6
    lventry 7
    // 0x400 Lower EL AArch64 — Sync: the guest's HVC (PSCI) and any Stage-2 abort. Straight to the
    // trampoline (must not clobber the guest's x0 = PSCI function id).
    .balign 0x80
    b       __linux_sync_entry
    // 0x480 Lower EL AArch64 — IRQ. ③-a2 made this live: `HCR_EL2.IMO` routes EVERY physical IRQ
    // the guest would have taken to EL2 instead, and this is where they arrive.
    .balign 0x80
    b       __linux_irq_entry
    lventry 10
    lventry 11
    lventry 12
    lventry 13
    lventry 14
    lventry 15

    .balign 0x80
__linux_diag:
    bl      handle_exception     // -> ! (reports EC/ELR/FAR/ESR and parks); w0 = slot index
0:  wfe
    b       0b
    "#
);

// The lower-EL sync trampoline: save x0..x30, call the Rust handler (which may set x0 = the PSCI
// return value), restore, and `eret` to resume the kernel past its `HVC`. Same save/restore
// discipline as `guest.rs`'s `__guest_sync_entry`.
global_asm!(
    r#"
    .section .text
    .balign 0x40
    .global __linux_sync_entry
__linux_sync_entry:
    sub     sp, sp, #(16 * 16)
    stp     x0, x1,   [sp, #(16 * 0)]
    stp     x2, x3,   [sp, #(16 * 1)]
    stp     x4, x5,   [sp, #(16 * 2)]
    stp     x6, x7,   [sp, #(16 * 3)]
    stp     x8, x9,   [sp, #(16 * 4)]
    stp     x10, x11, [sp, #(16 * 5)]
    stp     x12, x13, [sp, #(16 * 6)]
    stp     x14, x15, [sp, #(16 * 7)]
    stp     x16, x17, [sp, #(16 * 8)]
    stp     x18, x19, [sp, #(16 * 9)]
    stp     x20, x21, [sp, #(16 * 10)]
    stp     x22, x23, [sp, #(16 * 11)]
    stp     x24, x25, [sp, #(16 * 12)]
    stp     x26, x27, [sp, #(16 * 13)]
    stp     x28, x29, [sp, #(16 * 14)]
    str     x30,      [sp, #(16 * 15)]
    mov     x0, sp
    bl      handle_linux_sync
    ldp     x0, x1,   [sp, #(16 * 0)]
    ldp     x2, x3,   [sp, #(16 * 1)]
    ldp     x4, x5,   [sp, #(16 * 2)]
    ldp     x6, x7,   [sp, #(16 * 3)]
    ldp     x8, x9,   [sp, #(16 * 4)]
    ldp     x10, x11, [sp, #(16 * 5)]
    ldp     x12, x13, [sp, #(16 * 6)]
    ldp     x14, x15, [sp, #(16 * 7)]
    ldp     x16, x17, [sp, #(16 * 8)]
    ldp     x18, x19, [sp, #(16 * 9)]
    ldp     x20, x21, [sp, #(16 * 10)]
    ldp     x22, x23, [sp, #(16 * 11)]
    ldp     x24, x25, [sp, #(16 * 12)]
    ldp     x26, x27, [sp, #(16 * 13)]
    ldp     x28, x29, [sp, #(16 * 14)]
    ldr     x30,      [sp, #(16 * 15)]
    add     sp, sp, #(16 * 16)
    eret
    "#
);

// The lower-EL IRQ trampoline (③-a2). Same save/restore discipline as the sync one, and for the same
// reason — the Rust handler clobbers caller-saved registers the interrupted guest is still using. It
// differs from the sync path in one way that matters: an IRQ's preferred return address is the
// INTERRUPTED instruction, which `ELR_EL2` already holds, so there is no `advance_elr_past_fault`
// here. Advancing it would silently skip one guest instruction per timer tick.
//
// ③-b2b-i added the `mov x0, sp`. Until then this trampoline saved the guest's GPRs and then called
// the handler with NO argument, so the IRQ path could report a fault but could not *change* the
// register state it returned to — which is precisely what a preemptive context switch has to do.
// The sync path has passed its frame since ③-a1; this is that, one exception class over.
global_asm!(
    r#"
    .section .text
    .balign 0x40
    .global __linux_irq_entry
__linux_irq_entry:
    sub     sp, sp, #(16 * 16)
    stp     x0, x1,   [sp, #(16 * 0)]
    stp     x2, x3,   [sp, #(16 * 1)]
    stp     x4, x5,   [sp, #(16 * 2)]
    stp     x6, x7,   [sp, #(16 * 3)]
    stp     x8, x9,   [sp, #(16 * 4)]
    stp     x10, x11, [sp, #(16 * 5)]
    stp     x12, x13, [sp, #(16 * 6)]
    stp     x14, x15, [sp, #(16 * 7)]
    stp     x16, x17, [sp, #(16 * 8)]
    stp     x18, x19, [sp, #(16 * 9)]
    stp     x20, x21, [sp, #(16 * 10)]
    stp     x22, x23, [sp, #(16 * 11)]
    stp     x24, x25, [sp, #(16 * 12)]
    stp     x26, x27, [sp, #(16 * 13)]
    stp     x28, x29, [sp, #(16 * 14)]
    str     x30,      [sp, #(16 * 15)]
    mov     x0, sp
    bl      handle_linux_irq
    ldp     x0, x1,   [sp, #(16 * 0)]
    ldp     x2, x3,   [sp, #(16 * 1)]
    ldp     x4, x5,   [sp, #(16 * 2)]
    ldp     x6, x7,   [sp, #(16 * 3)]
    ldp     x8, x9,   [sp, #(16 * 4)]
    ldp     x10, x11, [sp, #(16 * 5)]
    ldp     x12, x13, [sp, #(16 * 6)]
    ldp     x14, x15, [sp, #(16 * 7)]
    ldp     x16, x17, [sp, #(16 * 8)]
    ldp     x18, x19, [sp, #(16 * 9)]
    ldp     x20, x21, [sp, #(16 * 10)]
    ldp     x22, x23, [sp, #(16 * 11)]
    ldp     x24, x25, [sp, #(16 * 12)]
    ldp     x26, x27, [sp, #(16 * 13)]
    ldp     x28, x29, [sp, #(16 * 14)]
    ldr     x30,      [sp, #(16 * 15)]
    add     sp, sp, #(16 * 16)
    eret
    "#
);

extern "C" {
    fn __linux_sync_entry() -> !;
    fn __linux_irq_entry() -> !;
    static __linux_vectors: u8;
}
// `handle_exception` (the diagnostic reporter the vector stubs above `bl` into) is deliberately NOT
// declared here. It is `#[no_mangle]` in `exceptions.rs` and reached only from `global_asm!`, so the
// linker resolves it and a Rust `extern` declaration adds nothing — while being, to the compiler, an
// unused item. It was one of the things the crate-wide `allow(dead_code)` was hiding (⑭).

/// The saved GPR frame the sync trampoline hands the Rust handler: `x[i]` = `x<i>` for `i` in 0..=30.
#[repr(C)]
struct LinuxFrame {
    x: [u64; 31],
}

// PSCI function IDs (SMC Calling Convention) — the same set `guest.rs`'s Arc-5c handler services.
const PSCI_VERSION_FID: u64 = 0x8400_0000;
const PSCI_FEATURES_FID: u64 = 0x8400_000A;
const PSCI_SYSTEM_OFF_FID: u64 = 0x8400_0008;
const PSCI_VERSION_1_1: u64 = 0x0001_0001;
const PSCI_NOT_SUPPORTED: u64 = (-1i64) as u64;

/// The emulated PL011s the guests drive (③-a1), **one per guest since ③-b2b-ii-a** — which is the
/// whole point of the device having become EL2 state instead of hardware. A UART is not a shareable
/// resource; two guests can only both have one if each has its own.
///
/// One [`BootCell`] over the array rather than one per guest: the claim being enforced is "no two
/// live mutable borrows", and no handler here touches two guests' models at once, so a single cell
/// states the same thing with one `Sync` argument instead of [`NUM_GUESTS`] of them.
static VPL011: BootCell<[DeployedPl011; NUM_GUESTS]> =
    BootCell::new("VPL011", [PL011_AT_RESET; NUM_GUESTS]);

/// A PL011 out of reset. Named because an array repeat expression needs a constant operand.
const PL011_AT_RESET: DeployedPl011 = DeployedPl011::new();

/// The emulated GICv3s the guests drive (③-b1), **one per guest since ③-b2b-ii-a** — giving the
/// *second* guest its own is the whole reason the distributor had to become EL2 state, exactly as
/// ③-a1 made the console EL2 state for the same reason. A guest that reaches the real
/// `GICD_ISENABLER` can enable and route interrupts belonging to someone else; two independent
/// register files in EL2 memory is what stops that being expressible.
///
/// **⚠ This is the first [`BootCell`] on this path borrowed from BOTH a synchronous and an
/// ASYNCHRONOUS handler, which is `crate::cell`'s class-3 hazard — so the I1 argument is written out
/// rather than left implicit.** [`handle_vgic_access`] borrows it from the data-abort path;
/// [`handle_linux_irq`] borrows it from the IRQ path to consult the mediation seam. Those cannot
/// overlap: **taking any exception to EL2 sets `PSTATE.I`**, so while either handler runs a physical
/// IRQ cannot be delivered, and **no EL2 path here unmasks it** — EL2 executes only inside handlers
/// on this configuration, never in a loop between them. So a borrow is never live when the other
/// claimant starts, and `BootCell`'s conflict halt is unreachable rather than merely unlikely.
///
/// This is the same argument `guest.rs` makes for `handle_guest_irq` touching `GUEST_HV`. Note what
/// it turns on: if a future rung ever unmasks IRQs inside an EL2 handler, or adds an EL2 idle loop,
/// **this borrow becomes a halt** — which is why `VCPU_PENDING` next door uses plain atomics
/// instead. A counter would; a register file that must be read consistently would not.
static VGIC: BootCell<[DeployedGic; NUM_GUESTS]> =
    BootCell::new("VGIC", [GIC_AT_RESET; NUM_GUESTS]);

/// A distributor out of reset. Named because an array repeat expression needs a constant operand.
const GIC_AT_RESET: DeployedGic = DeployedGic::new();

/// The shared serial line, one buffered line per guest (③-b2b-ii-a).
///
/// See [`crate::console`] for why a per-byte relay stops working the moment two kernels run: the
/// preemption point can land between any two bytes of a line, and the gate is substring matching
/// over the result.
///
/// Borrowed from the data-abort path (a guest transmitting) and at `SYSTEM_OFF`, both synchronous;
/// the same I1 argument as [`VGIC`] applies, and more easily, since no asynchronous handler claims
/// it at all.
static CONSOLE: BootCell<GuestConsole> = BootCell::new("CONSOLE", GuestConsole::new());

/// How many physical timer interrupts EL2 has forwarded to the guest as virtual ones (③-a2).
///
/// **This is the arc's ingress witness, and it exists because nothing else can see the change**
/// (design-lesson #99). A guest whose scheduler tick arrives by EL2 list-register injection prints
/// exactly what a guest taking the PPI directly prints — every kernel marker in the ⑬ gate is
/// satisfied identically either way, which is the same trap ③-a1 fell into and had to bring its own
/// witness for. Only EL2 can count what only EL2 now sees.
///
/// Plain atomic, not a [`BootCell`]: this is written from an asynchronous EL2 exception handler, which
/// is `crate::cell`'s class-3 hazard. An atomic has no borrow to overlap, so the hazard does not arise
/// — the same reasoning `guest.rs`'s `VCPU_PENDING` records.
///
/// **Per guest since ③-b2b-ii-a.** A merged count would stay green with one guest's forwarding path
/// entirely dead — the same reason ③-a1/a2/b1 each brought their own line rather than one tally.
static TIMER_FORWARDED: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// How many guest-generated SGIs EL2 has mediated and delivered (③-a2) — the second thing `IMO=1`
/// made EL2 responsible for. Same standing as [`TIMER_FORWARDED`]: written from a trap handler, so an
/// atomic rather than a [`BootCell`], and per guest for the same reason.
static SGIS_DELIVERED: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// The Linux-mode lower-EL **IRQ** handler (③-a2) — the guest's device interrupts, taken at EL2
/// because `HCR_EL2.IMO` routes them there, and handed on as *virtual* interrupts.
///
/// **The timer is the load-bearing case, and it is why this is not the synthetic path.**
/// `guest.rs`'s handler answers the arch-timer PPI with [`gic::disable_vtimer`] — a **one-shot**: it
/// clears `CNTV_CTL_EL0` so the level-triggered interrupt de-asserts and cannot immediately re-fire.
/// A synthetic guest wanting one tick is served by that; Linux, whose scheduler needs a *periodic*
/// tick it re-arms itself, is destroyed by it. So the level has to be dropped by the GUEST reprogramming
/// `CNTV_CVAL_EL0`, which means the physical interrupt must stay **Active** until it does — and EL2
/// gets no signal when that happens. [`gic::inject_hw`] is the answer: the guest's own EOI of the
/// virtual interrupt deactivates the physical one, with no EL2 involvement. See [`gic::LR_HW`].
///
/// Anything that is not the timer is a bring-up fault, reported with its INTID and parked, on the same
/// reasoning as [`handle_linux_data_abort`]: with `IMO=1` EVERY physical interrupt now arrives here, so
/// silently completing an unexpected one would hide exactly the routing bug this path can have.
///
/// # Safety
/// Called from the IRQ trampoline with the guest's registers saved, **and now with the frame that
/// holds them**. ③-a2 took no frame, on the reasoning that an interrupt — unlike a trapped
/// instruction — carries no operands, which is true of *reading* the interrupt and false of what
/// ③-b2b-i does with it: a preemptive context switch has to replace the register state the handler
/// returns to. That is the whole difference between forwarding a tick and scheduling on it.
///
/// # Safety
/// `frame` is the valid `*mut LinuxFrame` the trampoline saved on the exception stack, live until
/// its epilogue reloads from it.
#[no_mangle]
extern "C" fn handle_linux_irq(frame: *mut LinuxFrame) {
    let intid = gic::ack_physical();
    // The interrupt belongs to whichever guest is executing: the physical timer's `CNTV_CVAL_EL0` is
    // part of the vCPU context, so the deadline that just expired is the running guest's own.
    let slot = current_slot();

    if intid == gic::VTIMER_INTID {
        // ③-b1 — THE MEDIATION SEAM. Before this rung EL2 forwarded the timer unconditionally, which
        // was correct with one guest and is exactly the decision that has to become per-guest for
        // two. Now the interrupt is delivered only if the guest asked for it **in its own emulated
        // distributor**, which lives in EL2 memory the guest cannot reach. A guest that has not
        // enabled INTID 27 does not get INTID 27 — and, come ③-b, cannot enable anyone else's.
        if !VGIC.borrow_mut()[slot].is_enabled(intid) {
            // Not an error — the guest legitimately runs with its timer masked. Mask it PHYSICALLY
            // too before completing it: the timer PPI is level-triggered, so deactivating while the
            // level is high would re-signal immediately and storm EL2. `handle_vgic_access` re-enables
            // it the moment the guest enables the INTID, so this is self-healing rather than a
            // one-way door.
            gic::set_ppi_enabled(intid, false);
            gic::eoi_physical(intid);
            gic::deactivate_physical(intid);
            return;
        }
        if !gic::inject_hw(gic::VTIMER_INTID, gic::VTIMER_INTID) {
            // Unreachable with one guest forwarding one interrupt into a bank of four — and reported
            // rather than dropped anyway, because a lost timer tick is a guest that stops scheduling,
            // which presents as a hang with no cause on the console.
            let mut uart = crate::uart();
            let _ = writeln!(
                uart,
                "baleen: LINUX GUEST TRAP: the list-register bank is full — cannot forward the timer \
                 interrupt (INTID {intid}); halting"
            );
            crate::park();
        }
        TIMER_FORWARDED[slot].fetch_add(1, Ordering::Relaxed);
        // Priority drop ONLY (`EOImode=1`): the interrupt stays Active, so its still-asserted level
        // cannot re-signal and storm EL2, while EL2's running priority returns to idle. The guest's
        // EOI of the virtual interrupt is what deactivates this one.
        gic::eoi_physical(intid);
        // ③-b2b-i: the tick is also the PREEMPTION POINT. `IMO=1` (③-a2) is what put EL2 here on
        // every tick; until now it only forwarded. See `preempt_through_the_scheduler`.
        // SAFETY: `frame` is the valid `*mut LinuxFrame` the trampoline just saved on the exception
        // stack, live until its epilogue reloads from it.
        preempt_through_the_scheduler(slot, unsafe { &mut *frame });
        return;
    }

    // 1020..=1023 are the architectural special INTIDs; 1023 is "spurious" and must NOT be completed.
    if intid >= 1020 {
        return;
    }

    let mut uart = crate::uart();
    let _ = writeln!(
        uart,
        "baleen: LINUX GUEST TRAP: unexpected physical interrupt INTID {intid} routed to EL2 by \
         HCR_EL2.IMO — no forwarding rule; halting"
    );
    crate::park();
}

/// ③-b2b-i — how many timer ticks apart the vCPU is preempted.
///
/// Not every tick: the switch is ~30 system-register accesses plus a poison pass, and doing it on
/// all ~400 ticks of a boot would change the guest's timing profile enough that a regression in the
/// boot itself could be mistaken for one in the switch. Every eighth still exercises it ~50 times per
/// boot, which is ~50 chances for a missing register to kill the kernel.
const PREEMPT_EVERY: u64 = 8;

/// The real guest's saved vCPU context (③-b2b-i).
///
/// **Borrowed from the IRQ handler only.** Exception entry to EL2 sets `PSTATE.I`, so no EL2 code can
/// be interrupted while holding this — the class-3 re-entrancy hazard `crate::cell` documents needs
/// a handler that runs with interrupts unmasked, and neither Linux-path handler does.
/// **One per guest since ③-b2b-ii-a**, because a context is what a switch *between* guests moves:
/// with one slot, a switch-to-self resumes the same registers it saved, and the array is what makes
/// "resume the OTHER guest" expressible at all.
static VCPU_CTX: BootCell<[vcpu::VcpuCtx; NUM_GUESTS]> =
    BootCell::new("LINUX_VCPU_CTX", [VCPU_CTX_EMPTY; NUM_GUESTS]);

/// An empty context. Named because an array repeat expression needs a constant operand.
const VCPU_CTX_EMPTY: vcpu::VcpuCtx = vcpu::VcpuCtx::new();

/// How many times each guest's vCPU has been switched out and back through hv-core's scheduler.
static SWITCHES: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// **③-b2b-i — preempt the guest at the timer tick, through `hv-core`'s REAL scheduler.**
///
/// The real-Linux path had no vCPU switch at all: `run` did one `eret` and never returned, and the
/// only scheduler call this file ever made was `DomainCreate`. `guest.rs` has had a two-domain
/// time-slice since M5 Arc 2 — but its saved context is four system registers, which is complete for
/// register-only synthetic guests and would leave a real kernel running on the peer's page tables.
///
/// **The switch is to the SAME vCPU, and the poison is what stops that being vacuous.** A
/// switch-to-self that saved nothing would look exactly like a correct one; between save and restore
/// every register in [`vcpu::CtxReg::ALL`] is clobbered, so a missing entry kills the guest instead
/// of going unnoticed (design-lesson #105, and the module docs of [`crate::vcpu`]).
///
/// **It goes through the model, not around it.** `SchedOffline` then `SchedRun` are the transitions
/// Phase I-1 made exhaustive and Tier-D quantifies over; a switch that only moved registers would be
/// a `memcpy` with a marker attached.
fn preempt_through_the_scheduler(slot: usize, frame: &mut LinuxFrame) {
    if !TIMER_FORWARDED[slot]
        .load(Ordering::Relaxed)
        .is_multiple_of(PREEMPT_EVERY)
    {
        return;
    }
    let dom = slot_dom(slot);

    // `try_borrow_mut`, and a skip rather than a halt if it is held: the cell is claimed during model
    // setup, and a tick that lands there should defer, not kill a boot that is otherwise fine. The
    // witness counts switches actually performed, so a systematically-skipped switch shows up as a
    // count of zero rather than as silence.
    let Some(mut cell) = crate::guest::GUEST_HV.try_borrow_mut() else {
        return;
    };
    let Some(hv) = cell.as_mut() else {
        return;
    };

    let now = {
        use hv_hal::TimeSource;
        crate::time::GenericTimer.now()
    };
    let mut sched = |call: HvCall, what: &str| {
        if let Err(e) = crate::teardown::dispatch(hv, dom, call) {
            let mut uart = crate::uart();
            let _ = writeln!(
                uart,
                "baleen: LINUX GUEST TRAP: scheduler '{what}' refused for dom {dom}: {e:?}; halting"
            );
            crate::park();
        }
    };
    // `SchedPreempt`, not `SchedOffline`. The model already had the right transition and its doc
    // names this exact situation — *"the involuntary counterpart of a guest yield"*: `Running` →
    // `Runnable`, freeing the pCPU without retiring the vCPU. `guest.rs` uses `SchedOffline` because
    // its synthetic vCPUs genuinely finish; a kernel interrupted mid-instruction has not finished,
    // and offlining it left the model in `Offline`, from which `SchedRun` is refused (`WrongState`).
    // That refusal is the model declining to describe a lie, which is what it is for.
    sched(
        HvCall::SchedPreempt {
            vcpu: LINUX_VCPU,
            now,
        },
        "preempt the running vcpu",
    );
    sched(
        HvCall::SchedRun {
            vcpu: LINUX_VCPU,
            pcpu: PCPU0,
            now,
        },
        "run the vcpu again",
    );
    drop(cell);

    let mut ctx = VCPU_CTX.borrow_mut();
    ctx[slot].save(&frame.x);
    // SAFETY: at EL2 with the context saved, and the restore below is unconditional — the guest's
    // EL1 configuration is garbage only for the handful of instructions between the two.
    unsafe { vcpu::poison() };
    // SAFETY: at EL2, restoring the context just saved for the vCPU about to be resumed. Still the
    // SAME slot: ③-b2b-ii-c is the rung that makes the restored slot differ from the saved one, and
    // it is the physical timer's Active state — not this line — that stands in its way (Probe 0).
    unsafe { ctx[slot].restore(&mut frame.x) };
    SWITCHES[slot].fetch_add(1, Ordering::Relaxed);
}

/// The Linux-mode lower-EL synchronous handler. `HVC` → service PSCI (Linux's `method = "hvc"`); an
/// `EC=0x24` **Stage-2 data abort** → the emulated PL011, if that is what the guest touched.
/// Anything else (an abort outside the emulated device, an unexpected trapped instruction) is a
/// bring-up bug: report it with full syndrome and park, so the fault is diagnosable rather than a
/// silent hang.
///
/// # Safety
/// `frame` is the valid `&mut LinuxFrame` the trampoline saved on the exception stack.
#[no_mangle]
extern "C" fn handle_linux_sync(frame: *mut LinuxFrame) {
    let (esr, elr, far) = read_syndrome();
    let ec = (esr >> 26) & 0x3f;
    let mut uart = crate::uart();

    // EC 0x24 = a Stage-2 data abort from EL1 — the trap-and-emulate transport. Before ③-a1 this
    // path did not exist at all and every non-`HVC` trap was fatal, which is why no mediated device
    // could work.
    if ec == EC_DATA_ABORT {
        // SAFETY: the trampoline gave us its on-stack frame; single-CPU, non-nested.
        let frame = unsafe { &mut *frame };
        handle_linux_data_abort(frame, esr, elr, far, &mut uart);
        return;
    }

    // EC 0x18 = a trapped MSR/MRS. Under `IMO=1` the guest's `ICC_SGI1R_EL1` writes land here (③-a2).
    if ec == EC_SYSREG {
        // SAFETY: the trampoline gave us its on-stack frame; single-CPU, non-nested.
        let frame = unsafe { &mut *frame };
        handle_linux_sysreg_trap(frame, esr, elr, far, &mut uart);
        return;
    }

    // EC 0x16 = HVC (AArch64).
    if ec == 0x16 {
        // SAFETY: the trampoline gave us its on-stack frame; single-CPU, non-nested.
        let frame = unsafe { &mut *frame };
        match frame.x[0] {
            PSCI_VERSION_FID => frame.x[0] = PSCI_VERSION_1_1,
            PSCI_FEATURES_FID => {
                frame.x[0] = if frame.x[1] == PSCI_SYSTEM_OFF_FID {
                    0
                } else {
                    PSCI_NOT_SUPPORTED
                };
            }
            PSCI_SYSTEM_OFF_FID => {
                // The guest's last line is often the one announcing the poweroff, and it arrives
                // without a terminating newline in front of this `HVC`. Flush before reporting, or
                // the witness swallows the last thing the boot said.
                let mut console = CONSOLE.borrow_mut();
                for slot in 0..NUM_GUESTS {
                    console.flush(slot, &mut uart);
                }
                drop(console);
                report_vpl011(&mut uart);
                report_interrupt_mediation(&mut uart);
                report_per_guest_state(&mut uart);
                let _ = writeln!(
                    uart,
                    "baleen: linux guest issued PSCI SYSTEM_OFF — a real Linux kernel booted and shut \
                     down on hv-metal's EL2 (M5 Arc 5e)"
                );
                semihosting_exit(); // clean QEMU exit (falls through to a fault→park if -semihosting off)
            }
            other => {
                frame.x[0] = PSCI_NOT_SUPPORTED;
                let _ = writeln!(
                    uart,
                    "baleen: linux PSCI FID 0x{other:08x} -> NOT_SUPPORTED"
                );
            }
        }
        return;
    }

    // Not an HVC: a genuine fault. Report and halt (the diagnostic that drives bring-up).
    let _ = writeln!(
        uart,
        "baleen: LINUX GUEST TRAP: EC=0x{ec:02x} ELR=0x{elr:016x} FAR=0x{far:016x} ESR=0x{esr:08x} — halting"
    );
    crate::park();
}

/// Route a guest **Stage-2 data abort** (`EC=0x24`). An access inside the emulated PL011's window is
/// trap-and-emulated; anything else is a real fault in a guest that is supposed to have everything
/// it touches either mapped or emulated, so it is reported with full syndrome and parked (the
/// `LINUX GUEST TRAP` string the gate forbids).
///
/// **The address arithmetic is not the synthetic path's.** `guest.rs` reads the whole faulting
/// address out of `FAR_EL2`, which is sound *there* because the synthetic guests run with stage-1
/// off, so VA == IPA. A real Linux kernel turns its MMU on within milliseconds of entry, and from
/// then on `FAR_EL2` holds a **guest virtual** address that has nothing to do with the device. The
/// IPA comes from `HPFAR_EL2`, which carries only `IPA[47:12]`; the in-page register offset comes
/// from `FAR_EL2[11:0]`, equal to the IPA's low bits because a 4 KiB granule does not translate
/// them ([`abort::full_ipa`]).
fn handle_linux_data_abort(frame: &mut LinuxFrame, esr: u64, elr: u64, far: u64, uart: &mut Pl011) {
    let a = DataAbort::decode(esr);
    let hpfar = read_hpfar();
    let ipa = abort::full_ipa(hpfar, far);

    // ③-b1: the emulated GIC. Checked before the PL011 only because it is the busier device; the
    // two windows are disjoint, so the order is arbitrary.
    if vgic::in_window(ipa) {
        handle_vgic_access(frame, &a, ipa, esr, elr, far, uart);
        return;
    }

    if !vpl011::in_window(ipa) {
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: EC=0x{ec:02x} data abort outside every emulated device — \
             IPA=0x{ipa:016x} ELR=0x{elr:016x} FAR=0x{far:016x} ESR=0x{esr:08x} — halting",
            ec = EC_DATA_ABORT
        );
        crate::park();
    }

    // Three ways an access can be undecodable. Each is fatal rather than guessed at: emulating the
    // wrong register, or writing a result into the wrong guest register, is far worse than halting
    // with the syndrome on the console. None of them is reachable from the PL011 accesses a Linux
    // driver actually makes (single-register `readw`/`writew`/`readl`/`writeb` at aligned offsets),
    // which is exactly why a silent fallback would be untested code on a live path.
    if !a.isv || a.fnv || a.s1ptw {
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: undecodable PL011 access at IPA=0x{ipa:016x} \
             (ISV={} FnV={} S1PTW={}) ESR=0x{esr:08x} — halting",
            a.isv as u8, a.fnv as u8, a.s1ptw as u8
        );
        crate::park();
    }
    let offset = ipa - vpl011::VPL011_BASE;
    if !offset.is_multiple_of(a.access_bytes()) {
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: misaligned PL011 access at IPA=0x{ipa:016x} \
             ({} bytes) — halting",
            a.access_bytes()
        );
        crate::park();
    }

    let slot = current_slot();
    let mut dev = VPL011.borrow_mut();
    let transmitted = if a.wnr {
        // A store: the value is the guest's source register (`SRT` 31 is `XZR`, which reads zero).
        let value = if a.srt < 31 { frame.x[a.srt] } else { 0 } & a.value_mask();
        dev[slot].mmio_write(offset, value)
    } else {
        // A load: service the register and write the result into the guest's saved frame. `SF`
        // clear means the destination is a 32-bit view of the register, so the load zero-extends —
        // which is what storing the masked value into the 64-bit slot already does.
        let value = dev[slot].mmio_read(offset, a.access_bytes());
        if a.srt < 31 {
            frame.x[a.srt] = if a.sf { value } else { value & 0xffff_ffff };
        }
        None
    };
    drop(dev);

    // The one place the emulated device meets the real one — and since ③-b2b-ii-a it goes through
    // the per-guest line buffer rather than straight at the hardware. A byte-at-a-time relay is
    // correct for one guest and unreadable for two: the preemption point can land between any two
    // bytes of a line. See [`crate::console`].
    if let Some(byte) = transmitted {
        CONSOLE.borrow_mut().put(slot, byte, uart);
    }

    // Unlike an `HVC`, a data abort's preferred return is the FAULTING instruction — resume past it
    // or the guest re-executes the access forever.
    crate::guest::advance_elr_past_fault();
}

/// Service a guest access to the **emulated GIC** (③-b1).
///
/// Structurally the PL011 path's twin, and it repeats that path's two refusals deliberately rather
/// than sharing a helper: an undecodable access is fatal (emulating the wrong register is worse than
/// halting with the syndrome), and so is a register [`crate::vgic`] does not model — a guest using a
/// register this distributor lacks is a guest whose expectations we would be silently violating.
#[allow(clippy::too_many_arguments)]
fn handle_vgic_access(
    frame: &mut LinuxFrame,
    a: &DataAbort,
    ipa: u64,
    esr: u64,
    elr: u64,
    far: u64,
    uart: &mut Pl011,
) {
    if !a.isv || a.fnv || a.s1ptw {
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: undecodable GIC access at IPA=0x{ipa:016x} \
             (ISV={} FnV={} S1PTW={}) ESR=0x{esr:08x} — halting",
            a.isv as u8, a.fnv as u8, a.s1ptw as u8
        );
        crate::park();
    }

    let slot = current_slot();
    let mut dev = VGIC.borrow_mut();
    let outcome = if a.wnr {
        let value = if a.srt < 31 { frame.x[a.srt] } else { 0 } & a.value_mask();
        dev[slot]
            .mmio_write(ipa, a.access_bytes(), value)
            .map(|()| 0)
    } else {
        dev[slot]
            .mmio_read(ipa, a.access_bytes())
            .inspect(|&value| {
                if a.srt < 31 {
                    frame.x[a.srt] = if a.sf { value } else { value & 0xffff_ffff };
                }
            })
    };
    // Mirror the guest's timer enable onto the PHYSICAL redistributor. The guest's writes no longer
    // reach hardware, so if EL2 did not carry this across, a guest enabling its timer would change
    // nothing and one that disabled it would keep being interrupted. Read back from the model rather
    // than interpreting the write, so one place decides what "enabled" means.
    //
    // It is the RUNNING guest's model, and a data abort can only come from the running guest — but
    // there is one physical redistributor for both, so once ③-b2b-ii-c makes `CURRENT` move, this
    // mirror has to be re-applied on every switch-in as well.
    let timer_enabled = dev[slot].is_enabled(gic::VTIMER_INTID);
    drop(dev);
    if a.wnr {
        gic::set_ppi_enabled(gic::VTIMER_INTID, timer_enabled);
    }

    if let Err(u) = outcome {
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: unmodelled {} register at offset 0x{:04x} \
             (IPA=0x{ipa:016x} {} {} bytes) ELR=0x{elr:016x} FAR=0x{far:016x} ESR=0x{esr:08x} \
             — halting",
            u.frame,
            u.offset,
            if a.wnr { "write" } else { "read" },
            a.access_bytes()
        );
        crate::park();
    }

    // A data abort's preferred return is the FAULTING instruction.
    crate::guest::advance_elr_past_fault();
}

/// `ESR_EL2.EC` for a **trapped MSR/MRS or System instruction** in AArch64 state.
const EC_SYSREG: u64 = 0x18;

/// The `ICC_SGI1R_EL1` system-register encoding as it appears in an `EC=0x18` ISS: `Op0=3, Op1=0,
/// CRn=12, CRm=11, Op2=5`, direction = write. Matched as one packed value rather than six field
/// comparisons, so a register this port has NOT thought about cannot fall through into the SGI path.
const ISS_SYSREG_FIELDS: u64 = 0x003f_ffff;
const ISS_ICC_SGI1R_EL1_WRITE: u64 = (3 << 20) | (5 << 17) | (12 << 10) | (11 << 1);

/// Route a guest **trapped system-register access** (`EC=0x18`) — a class of trap that did not exist
/// on this path before ③-a2, because `IMO=0` left the guest's GIC CPU interface untrapped.
///
/// The only member of the class this port has a rule for is a write to `ICC_SGI1R_EL1`: the guest
/// raising a software-generated interrupt. See [`gic::sgi1r_intid`] for why the architecture routes it
/// here and what the single-vCPU emulation is. Everything else is reported with the decoded register
/// encoding and parked — the same discipline as an abort outside every emulated device, and for the
/// same reason: a silently-ignored system-register write leaves the guest believing something took
/// effect that did not.
fn handle_linux_sysreg_trap(
    frame: &mut LinuxFrame,
    esr: u64,
    elr: u64,
    far: u64,
    uart: &mut Pl011,
) {
    let iss = esr & 0x01ff_ffff;

    if iss & ISS_SYSREG_FIELDS == ISS_ICC_SGI1R_EL1_WRITE && iss & 1 == 0 {
        // `Rt` is ISS[9:5]; 31 is `XZR`, which reads zero.
        let rt = ((iss >> 5) & 0x1f) as usize;
        let value = if rt < 31 { frame.x[rt] } else { 0 };
        let intid = gic::sgi1r_intid(value);
        if !gic::inject(intid) {
            let _ = writeln!(
                uart,
                "baleen: LINUX GUEST TRAP: the list-register bank is full — cannot deliver the \
                 guest's SGI {intid}; halting"
            );
            crate::park();
        }
        SGIS_DELIVERED[current_slot()].fetch_add(1, Ordering::Relaxed);
        // A trapped instruction's preferred return is the instruction ITSELF; resume past it or the
        // guest re-executes the `msr` forever.
        crate::guest::advance_elr_past_fault();
        return;
    }

    let _ = writeln!(
        uart,
        "baleen: LINUX GUEST TRAP: unhandled system-register access (Op0={} Op1={} CRn={} CRm={} \
         Op2={} {}) ELR=0x{elr:016x} FAR=0x{far:016x} ESR=0x{esr:08x} — halting",
        (iss >> 20) & 0x3,
        (iss >> 14) & 0x7,
        (iss >> 10) & 0xf,
        (iss >> 1) & 0xf,
        (iss >> 17) & 0x7,
        if iss & 1 == 0 { "write" } else { "read" },
    );
    crate::park();
}

/// Read `HPFAR_EL2` — the architectural source of the faulting **IPA** for a Stage-2 abort.
fn read_hpfar() -> u64 {
    let hpfar: u64;
    // SAFETY: `HPFAR_EL2` is a read-only EL2 system register, readable at EL2; no memory effect.
    unsafe {
        asm!("mrs {0}, hpfar_el2", out(reg) hpfar, options(nomem, nostack, preserves_flags));
    }
    hpfar
}

/// Report what the emulated PL011 witnessed, at the guest's `SYSTEM_OFF` — the last moment EL2 gets
/// before the boot ends.
///
/// **Since ③-b2b-ii-a it reports the RUNNING guest's model**, i.e. the one that issued this
/// `SYSTEM_OFF`. With one runner that is the whole story; ③-b2b-ii-c, where each guest powers off
/// separately, is where this has to say *which* guest it is talking about — the same split
/// [`report_per_guest_state`] already makes, and the reason that one exists.
///
/// **Why this marker and not a simpler one.** Every other assertion in the real-Linux gate
/// (`Linux version`, `Machine model`, `Run /init`, `BALEEN-STEP0-OK`) is satisfied identically
/// whether the PL011 is emulated or passed through — they are statements about the kernel, and the
/// kernel neither knows nor cares which. So none of them could witness ③-a1. This one can: the
/// device counts the bytes it forwards and watches its own transmit stream for userspace's marker,
/// so the `OK` line is printed only by an emulator that actually carried the guest's console
/// (design-lesson #24f; #71 from the failure side — a check whose inputs cannot discriminate).
///
/// **It claims INGRESS, and says so.** A probe that deleted the `uart.put` — the emulator receiving
/// the guest's bytes and dropping them on the floor — left this line green while seven kernel
/// markers went red, because the needle is matched where the byte ARRIVES. That is the right split
/// (the seven markers are the egress half, and they are un-forgeable in their own way: the kernel
/// cannot print them without the emulator relaying them), but the wording had to stop implying it
/// covered both. A witness that overstates by one word is the same defect as one that cannot
/// discriminate, only harder to notice.
fn report_vpl011(uart: &mut Pl011) {
    let (ok, traps, dr_writes) = VPL011.borrow_mut()[current_slot()].witness();
    if ok {
        let _ = writeln!(
            uart,
            "baleen: vpl011 OK: the guest's console is EMULATED — userspace's 'BALEEN-STEP0-OK' was \
             written to the emulated PL011's DR register in EL2 ({traps} register traps, \
             {dr_writes} bytes relayed to the real PL011)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: vpl011 FAIL: the guest's console did not go through the emulator \
             ({traps} register traps, {dr_writes} bytes forwarded) — the PL011 is being passed \
             through, or the transmit path is broken"
        );
    }
}

/// Report the interrupt-mediation witnesses at the guest's `SYSTEM_OFF` — ③-a2's two (timer
/// forwarding, SGI mediation) and ③-b1's (the emulated distributor).
///
/// Three mechanisms reached by three different paths — the IRQ vector, an `EC=0x18` system-register
/// trap, and a Stage-2 data abort — so each reports its own line. Merging them into one counter
/// would let the witness stay green with any single path dead.
///
/// **The ingress half, and it is the only half EL2 can claim.** The count is incremented in
/// [`handle_linux_irq`], which runs *only* because `HCR_EL2.IMO` routed a physical interrupt to EL2 —
/// under `IMO=0` this function is unreachable and the count is zero. So a non-zero count cannot be
/// produced by a guest taking its timer directly, which is exactly what the twelve kernel markers
/// cannot distinguish (design-lesson #99).
///
/// **The EGRESS half is the kernel markers, and they are un-forgeable in their own way** — the same
/// split ③-a1 settled on, stated the same way. Forwarding an interrupt EL2 never delivers would leave
/// this line green and hang the boot: a Linux guest whose scheduler tick never arrives does not reach
/// `Run /init`, so `BALEEN-STEP0-OK` and every marker after it go red. Neither half claims the other's
/// ground.
fn report_interrupt_mediation(uart: &mut Pl011) {
    let slot = current_slot();
    let n = TIMER_FORWARDED[slot].load(Ordering::Relaxed);
    if n > 0 {
        let _ = writeln!(
            uart,
            "baleen: vtimer OK: the guest's scheduler tick is FORWARDED — {n} physical timer \
             interrupts (INTID {}) taken at EL2 under HCR_EL2.IMO=1 and injected as hardware-mapped \
             virtual interrupts",
            gic::VTIMER_INTID
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: vtimer FAIL: EL2 forwarded no timer interrupt — the guest is taking the PPI \
             directly (IMO=0), or the physical CPU interface never delivered one"
        );
    }

    // ③-b1: the interrupt CONTROLLER the guest programmed was ours too — a THIRD mechanism, reached
    // by a third path (a Stage-2 data abort on the GIC window). Each of the three gets its own line
    // for the same reason: a witness that merged them could stay green with any one path dead.
    let (gic_traps, gic_enables) = VGIC.borrow_mut()[slot].witness();
    if gic_traps > 0 && gic_enables > 0 {
        let _ = writeln!(
            uart,
            "baleen: vgic OK: the guest's interrupt controller is EMULATED — {gic_traps} GICD/GICR \
             register traps in EL2, {gic_enables} INTIDs enabled in a distributor the guest cannot \
             reach (Stage-2 device pass-through window: 0 bytes)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: vgic FAIL: the guest's GIC accesses did not go through the emulator \
             ({gic_traps} traps, {gic_enables} enables) — the distributor is being passed through"
        );
    }

    // ③-b2b-i: the guest was SWITCHED OUT AND BACK, through hv-core's scheduler, with every context
    // register poisoned in between. A FOURTH mechanism, and the only one whose evidence is that the
    // guest survived rather than that a counter moved — every marker after this line is a kernel that
    // resumed from a context this metal reconstructed from scratch.
    let switches = SWITCHES[slot].load(Ordering::Relaxed);
    if switches > 0 {
        let _ = writeln!(
            uart,
            "baleen: vcpu OK: the guest was PREEMPTED and restored {switches} times through \
             hv-core's scheduler — {} context registers plus the vGIC bank (list registers + \
             ICH_VMCR_EL2) saved, poisoned and reinstated each time, and the kernel never noticed",
            vcpu::CtxReg::ALL.len()
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: vcpu FAIL: the guest was never preempted — the timer tick did not reach the \
             switch, so nothing here was exercised"
        );
    }

    // The SGI half is a SEPARATE mechanism reached by a separate trap (`EC=0x18`, not the IRQ
    // vector), so it gets its own line rather than being folded into the timer count above.
    let sgis = SGIS_DELIVERED[slot].load(Ordering::Relaxed);
    if sgis > 0 {
        let _ = writeln!(
            uart,
            "baleen: vsgi OK: {sgis} guest SGIs MEDIATED at EL2 — ICC_SGI1R_EL1 writes trap under \
             HCR_EL2.IMO=1 and are delivered as virtual interrupts"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: vsgi FAIL: EL2 mediated no SGI — the guest reached its own SGI generation \
             register, which HCR_EL2.IMO=1 is supposed to make impossible"
        );
    }
}

/// Put every guest's unterminated console line on the wire.
///
/// Called from [`crate::park`] — a guest that dies mid-line would otherwise take its last fragment
/// with it, and a fatal path is precisely where that fragment matters. `try_borrow_mut` and a silent
/// skip rather than a halt: `park()` is also `crate::cell`'s conflict halt, so this must never be
/// the thing that halts, and a lost fragment is a worse diagnostic than no fragment only if it stops
/// the message that named the fault — which it cannot, that one is already on the wire.
pub(crate) fn flush_consoles() {
    let Some(mut console) = CONSOLE.try_borrow_mut() else {
        return;
    };
    let mut uart = crate::uart();
    for slot in 0..NUM_GUESTS {
        console.flush(slot, &mut uart);
    }
}

/// The per-guest counters, named by the mechanism that writes each one. One array, so the count in
/// the report below is derived and a counter cannot be added without appearing there.
const PER_GUEST_COUNTERS: [&str; 8] = [
    "GIC register traps",
    "INTID enables",
    "PL011 register traps",
    "console bytes",
    "console lines",
    "forwarded timer ticks",
    "mediated SGIs",
    "scheduler switches",
];

/// **③-b2b-ii-a's own witness: the per-guest state is INDEXED, not SHARED.**
///
/// **Why this rung needs a witness at all, and why the obvious one is empty.** Everything ③-b2b-ii-a
/// changed is structural — eight globals became eight arrays — and with one guest running, the boot
/// it produces is byte-for-byte the boot it produced before. That is design-lesson #105's shape
/// exactly: a change whose "it still works" test cannot tell the change from its absence. An array
/// indexed by a constant is a global wearing brackets.
///
/// **So the witness is aimed at the peer, not the runner.** Dom 2 has never been dispatched, so
/// every one of its counters must be exactly zero — and that is a *falsifiable* statement about the
/// refactor rather than about the boot. A model still shared between the guests, or a handler
/// indexing with the wrong slot, contaminates the peer's counters with the runner's traffic: dom 1
/// makes hundreds of GIC traps and thousands of console bytes on this boot, so a single shared field
/// is the difference between `0` and a four-digit number. Nothing else in the gate can see that.
///
/// **Honest limit.** Zero peer counters prove no handler *on the paths this boot took* wrote through
/// a stale index. They do not prove the arrays are indexed correctly — with one runner, "always slot
/// 0" and "always the running slot" agree. What distinguishes those is a second runner, which is
/// ③-b2b-ii-c; this rung's job is to make sure the runner's state stops leaking sideways first.
fn report_per_guest_state(uart: &mut Pl011) {
    let pl011 = VPL011.borrow_mut();
    let vgic = VGIC.borrow_mut();
    let console = CONSOLE.borrow_mut();

    let sample = |slot: usize| -> [u64; PER_GUEST_COUNTERS.len()] {
        let (gic_traps, gic_enables) = vgic[slot].witness();
        let (_, pl011_traps, dr_writes) = pl011[slot].witness();
        [
            gic_traps,
            gic_enables,
            pl011_traps,
            dr_writes,
            console.lines(slot),
            TIMER_FORWARDED[slot].load(Ordering::Relaxed),
            SGIS_DELIVERED[slot].load(Ordering::Relaxed),
            SWITCHES[slot].load(Ordering::Relaxed),
        ]
    };

    let run = current_slot();
    let mine = sample(run);
    // The first peer counter that is not zero, if any — named, because "the peer is contaminated"
    // and "the peer's GIC model is the runner's" are different bugs and the counter says which.
    let mut leak = None;
    for slot in (0..NUM_GUESTS).filter(|&s| s != run) {
        for (name, value) in PER_GUEST_COUNTERS.iter().zip(sample(slot)) {
            if value != 0 && leak.is_none() {
                leak = Some((slot_dom(slot), *name, value));
            }
        }
    }

    match leak {
        None => {
            let _ = writeln!(
                uart,
                "baleen: perguest OK: the guests' device models, vCPU contexts and witnesses are \
                 INDEXED, not shared — dom {} ran and made {} GIC traps, {} INTID enables, {} PL011 \
                 traps, {} console bytes on {} lines, {} forwarded ticks, {} SGIs and {} switches, \
                 while all {} of dom {}'s counters are ZERO",
                slot_dom(run),
                mine[0],
                mine[1],
                mine[2],
                mine[3],
                mine[4],
                mine[5],
                mine[6],
                mine[7],
                PER_GUEST_COUNTERS.len(),
                slot_dom(if run == SLOT_A { SLOT_B } else { SLOT_A }),
            );
        }
        Some((dom, name, value)) => {
            let _ = writeln!(
                uart,
                "baleen: perguest FAIL: dom {dom} has never been dispatched, yet its '{name}' \
                 counter reads {value} — the per-guest state is shared, or a handler indexed it \
                 with the wrong slot"
            );
        }
    }
}

/// Cleanly exit QEMU via the ARM semihosting `SYS_EXIT` call (the `qemu-linux` target passes
/// `-semihosting`). Used on the guest's PSCI `SYSTEM_OFF` so the demo terminates instead of parking
/// until an external timeout. If `-semihosting` is not enabled, `hlt #0xf000` faults to EL2 and the
/// diagnostic vector parks — so this is safe either way.
fn semihosting_exit() -> ! {
    // AArch64 `SYS_EXIT` (op 0x18): `x1` -> `[reason, exit_code]`; `ADP_Stopped_ApplicationExit` =
    // 0x20026 → QEMU exits with the given code (0).
    static EXIT_BLOCK: [u64; 2] = [0x2_0026, 0];
    // SAFETY: `hlt #0xf000` is the AArch64 semihosting trap; EL2 runs MMU-off/identity so
    // `&EXIT_BLOCK` is a physical address QEMU reads directly. Never returns (QEMU exits, or the
    // instruction faults to the EL2 vector, which parks).
    unsafe {
        asm!(
            "mov x0, #0x18",
            "mov x1, {b}",
            "hlt #0xf000",
            b = in(reg) core::ptr::addr_of!(EXIT_BLOCK),
            options(nostack, noreturn),
        );
    }
}

/// Read `(ESR_EL2, ELR_EL2, FAR_EL2)`.
fn read_syndrome() -> (u64, u64, u64) {
    let (esr, elr, far): (u64, u64, u64);
    // SAFETY: EL2 syndrome registers, readable at EL2; no memory effect.
    unsafe {
        asm!(
            "mrs {0}, esr_el2",
            "mrs {1}, elr_el2",
            "mrs {2}, far_el2",
            out(reg) esr, out(reg) elr, out(reg) far,
            options(nomem, nostack, preserves_flags),
        );
    }
    (esr, elr, far)
}

// Install the Linux vector table and `eret` into the kernel. `x0` = DTB PA (arm64 boot protocol),
// `x1` = EL2 exception-stack top (becomes `SP_EL2` for later HVC/abort traps). `ELR_EL2`/`SPSR_EL2`
// are set by the caller before the `bl` here.
global_asm!(
    r#"
    .section .text
    .global __enter_linux
__enter_linux:
    // x0 = dtb_pa, x1 = exc_stack_top
    mov     sp, x1              // SP_EL2 for future traps
    mov     x1, xzr             // arm64 boot protocol: x1..x3 = 0
    mov     x2, xzr
    mov     x3, xzr
    dsb     sy
    isb
    eret                        // -> EL1 kernel entry (ELR_EL2), with x0 = DTB
    "#
);

extern "C" {
    fn __enter_linux(dtb_pa: u64, exc_stack_top: u64) -> !;
}

extern "C" {
    static __exc_stack_top: u8;
}

/// The Arc-5e entry: build the pass-through Stage-2, enable it (`IMO=0`), let the guest reach the
/// GIC/timer, point `ELR_EL2` at the loaded kernel `Image`, install the Linux vectors, and `eret`
/// into a real Linux kernel with `x0` = the DTB. Never returns (transfers to EL1).
pub(crate) fn run(uart: &mut Pl011) -> ! {
    let _ = writeln!(
        uart,
        "baleen: M5 Arc 5e — booting a REAL aarch64 Linux kernel as EL1 guest dom {GUEST_A} \
         (Image@0x{KERNEL_ENTRY:08x}, DTB@0x{DTB_ADDR:08x}, RAM 0x{GUEST_RAM_BASE:08x}..0x{split:08x}; \
         peer dom {GUEST_B} owns 0x{split:08x}..0x{GUEST_RAM_END:08x})",
        split = stage2::LINUX_RAM_SPLIT
    );

    // Build the guest's model and emit its Stage-2 through the PROVEN emitter (M5 Arc 6b).
    *crate::guest::GUEST_HV.borrow_mut() = Some(crate::build_hypervisor());
    let mut cell = crate::guest::GUEST_HV.borrow_mut();
    let hv = match cell.as_mut() {
        Some(hv) => hv,
        None => crate::park(),
    };
    // ③-b2a — TWO domains, TWO Stage-2 images, one running kernel.
    //
    // Domain A is the guest that boots; domain B owns the other half of the window and has a real
    // emitted image it could run from. Building B is not decoration: it is what makes the negative
    // test below a statement about a *peer's live mapping* rather than about unmapped space. An
    // address that is simply not backed faults for a boring reason; an address that IS mapped, by a
    // real Stage-2 image, at real RAM the emitter authorized — and still faults for A — is the
    // isolation claim.
    let mut vttbr = [0u64; NUM_GUESTS];
    for (slot, v) in vttbr.iter_mut().enumerate() {
        *v = build_model_and_stage2(
            hv,
            uart,
            slot_dom(slot),
            first_frame(slot),
            first_table(slot),
            slot,
        );
    }
    report_disjointness(&vttbr, uart);

    // ③-b2b-i — put the guest's vCPU under hv-core's REAL scheduler before it ever runs, so the
    // preemption at each timer tick is a `SchedOffline`/`SchedRun` pair against a model that already
    // has it Running, not a pair of calls the model would refuse. Admit moves it Offline → Runnable;
    // the dispatch moves it Runnable → Running.
    for (call, what) in [
        (
            HvCall::SchedAdmit { vcpu: LINUX_VCPU },
            "admit the linux vcpu",
        ),
        (
            HvCall::SchedRun {
                vcpu: LINUX_VCPU,
                pcpu: PCPU0,
                now: {
                    use hv_hal::TimeSource;
                    crate::time::GenericTimer.now()
                },
            },
            "dispatch the linux vcpu",
        ),
    ] {
        if let Err(e) = crate::teardown::dispatch(hv, GUEST_A, call) {
            let _ = writeln!(
                uart,
                "baleen: linux scheduler setup '{what}' failed for dom {GUEST_A}: {e:?}; halting"
            );
            crate::park();
        }
    }
    let _ = writeln!(
        uart,
        "baleen: linux vcpu {LINUX_VCPU} admitted and dispatched onto pCPU {PCPU0} through \
         hv-core's scheduler — the guest is now PREEMPTIBLE at every {PREEMPT_EVERY}th timer tick"
    );
    // Name the saved set in the transcript. A context register that stops being saved is otherwise
    // invisible until it corrupts a guest; here it changes this line, so the boot output itself
    // records what this build believes a vCPU is made of.
    let _ = write!(
        uart,
        "baleen: vcpu context = {} registers:",
        vcpu::CtxReg::ALL.len()
    );
    for r in vcpu::CtxReg::ALL {
        let _ = write!(uart, " {}", r.name());
    }
    let _ = writeln!(uart);

    drop(cell);
    enable_stage2(vttbr[SLOT_A]);
    enable_guest_hw_access();
    init_guest_el1();

    // Boot registers: SPSR = EL1h/DAIF-masked, ELR = kernel entry.
    // SAFETY: `SPSR_EL2`/`ELR_EL2` are RW at EL2; they seed the state `eret` restores.
    unsafe {
        asm!(
            "msr spsr_el2, {spsr}",
            "msr elr_el2, {elr}",
            spsr = in(reg) SPSR_EL2_LINUX,
            elr = in(reg) KERNEL_ENTRY,
            options(nomem, nostack, preserves_flags),
        );
    }

    // Install the Linux vector table (VBAR_EL2), replacing the synthetic-path table for this boot.
    // SAFETY: `VBAR_EL2` is RW at EL2; `__linux_vectors` is the 2 KiB-aligned in-image table.
    unsafe {
        let vec = core::ptr::addr_of!(__linux_vectors) as u64;
        asm!("msr vbar_el2, {v}", "isb", v = in(reg) vec, options(nomem, nostack));
    }

    // ③-a2: take the guest's interrupts at EL2 and forward them. **Strictly after the vector install
    // above** — `enable_el2` sets `HCR_EL2.IMO`, and from that instruction on a physical IRQ lands on
    // whatever `VBAR_EL2` currently points at. Enabling first would put a window, however short,
    // where a timer PPI would be dispatched through the synthetic path's table.
    //
    // ③-b1 INVERTED ③-a2's note here, and the inversion is the rung in one line. Under ③-a2 the
    // GICD/GICR were pass-through, so the KERNEL enabled PPI 27 at the redistributor and — with
    // `IMO=1` — that same enable was what made the interrupt reach EL2; calling this would have
    // fought the guest for a device the guest owned. Now the guest's GIC writes land in
    // `crate::vgic` and touch no hardware, so **EL2 owns the physical distributor** and must
    // initialize it itself. Taking a device away from a guest means inheriting its job.
    gic::init_physical_vtimer();
    gic::enable_physical_cpu_interface_el2();
    gic::set_eoi_mode_split();
    gic::enable_el2();

    let _ = writeln!(
        uart,
        "baleen: EL2 takes the guest's interrupts — HCR_EL2.IMO=1, timer PPI {} forwarded by \
         hardware-mapped list-register injection",
        gic::VTIMER_INTID
    );

    let _ = writeln!(uart, "baleen: entering EL1 — the kernel takes the machine");

    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    // SAFETY: transfers to EL1 via `eret`; `DTB_ADDR` is the loaded DTB, `exc_stack_top` the EL2
    // trap stack. Never returns.
    unsafe { __enter_linux(DTB_ADDR, exc_stack_top) }
}
