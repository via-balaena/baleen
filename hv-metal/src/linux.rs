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
//! **③-b2b-ii-d added the first node that tree has ever gained, and the distinction is worth
//! keeping sharp.** The property earned above is that *taking a device away from a guest never
//! required editing its description*; that is untouched. The peer-probe node is not an
//! accommodation of our emulation — it is the negative test's instrument, the one node in the tree
//! that exists in order to FAIL. Say "the DTS gained a probe", not "the DTS is untouched".
//!
//! So **four** things reach EL2 now: `HVC` (PSCI — Linux's `method = "hvc"`), an `EC=0x24` Stage-2
//! **data abort**, which [`handle_linux_sync`] routes to the emulated GIC or the emulated PL011 and
//! otherwise treats as a guest fault; an `EC=0x18` **trapped system register**
//! ([`handle_linux_sysreg_trap`], the guest's `ICC_SGI1R_EL1` writes); and every **physical IRQ**
//! ([`handle_linux_irq`]).
//!
//! ## ★ What happens when a guest does something EL2 has no rule for
//!
//! **The offending domain is retired; the machine keeps running** ([`fault_retire`]). This used to be
//! `crate::park()` at every one of those sites, and that was a defensible call **while there was one
//! guest** — halting hurt only the guest that caused it, and guessing at an undecodable access is
//! worse than stopping loudly. **The second guest changed the meaning of every one of them without
//! changing a line**: a halt now takes down a peer that did nothing, which is a cross-domain denial
//! of service. Same shape as honest-ledger item 9 — *sound with one guest, false with two*.
//!
//! They were cheap to reach, too. Six of the seven were a **single instruction**: `ISV=0` is simply
//! what a load/store PAIR produces, so `stp x0, x1, [gic_base]` halted the hypervisor.
//!
//! `crate::park()` still exists here, and now means one thing only: **EL2 itself is in a state it
//! cannot describe** (the model refused a transition, a `BootCell` was already borrowed). Those are
//! not guest-reachable. The diagnostics for guest faults are prefixed `guest FAULT:` rather than
//! `LINUX GUEST TRAP:` so that the latter keeps that narrower meaning — and stays forbidden by the
//! boot gate in *both* of its runs.
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
//! witness counters are arrays indexed by [`CURRENT`], and a guest's domain id, Stage-2 set, frame
//! range and table range are all functions of its slot.
//!
//! ## ③-b2b-ii-c1: the one physical timer learns to change hands
//!
//! What stood in the way of a second runner was not this file's indexing but the **physical** timer,
//! measured rather than assumed: at every preemption point PPI 27 is Active *and* Pending, with the
//! running guest holding the `HW=1` list register that owns its deactivation. A second guest
//! switched in there could never be signalled the tick — and the tick is the only thing that
//! re-enters EL2, so that is a hang of the machine, not a slow boot.
//!
//! [`preempt_through_the_scheduler`] is therefore a seven-step sequence whose *order* is the rung.
//! The outgoing guest's forwarded interrupt is demoted to a purely virtual one (it no longer owns
//! the line), EL2 deactivates the physical interrupt itself, and the PPI is re-armed from the
//! **incoming** guest's own emulated distributor — after the restore, because only then does
//! `CNTV_CVAL_EL0` describe the guest about to run. See [`gic::release_forwarded_timer`], which also
//! records the kill probe: delete that deactivate and guest A itself hangs after printing
//! `poweroff`.
//!
//! The **console** had to move with them ([`crate::console`]). ③-a1's relay is per-byte, and the
//! preemption point can land between any two bytes of a line, so two kernels would interleave
//! character by character — and `xtask::LINUX_MARKERS` is substring matching over that log. EL2
//! therefore buffers each guest's stream to a newline and tags the line with the model instance that
//! received it, which is also the only attribution a guest cannot forge: both guests run the *same*
//! initramfs.
//!
//! ## ③-b2b-ii-c2: `CURRENT` moves, and a second unmodified kernel runs
//!
//! Two real Linux kernels now time-slice one physical CPU. Each holds half the RAM window behind its
//! own emitted Stage-2 image, drives its own emulated PL011 and GICv3, and is switched by `hv-core`'s
//! real scheduler — `SchedPreempt` the outgoing vCPU, `SchedRun` the incoming one, and `VTTBR_EL2`
//! swapped with **no `tlbi`** because the two domains' VMIDs cannot alias (M5 Arc 2's property,
//! reached by real kernels for the first time).
//!
//! **Guest B is never `eret`-ed into.** Its context is *seeded* with the arm64 boot protocol's entry
//! state ([`vcpu::VcpuCtx::seed_boot`]) and its first instruction is executed by the same context
//! restore that resumes it ten thousand switches later — so its boot is not a second entry path that
//! must be kept in step with guest A's, and there is no code that runs once and is never exercised
//! again.
//!
//! **Selection is asked of the model but decided here.** [`next_runnable`] rotates over the slots
//! `hv_core::sched` reports `Runnable`; a guest that has issued `SYSTEM_OFF` is `Offline` and stops
//! being picked, which is the *only* record of who is still alive. `hv-core`'s own docs draw that
//! line — mechanism, not policy — so the rotation is `hv-metal`'s and the legality is the model's.
//!
//! **EL2 owns no clock, and with two guests that stopped being harmless.** Every re-entry to EL2
//! here is caused by the guest — a trap it takes, or the arch-timer PPI it programmed for itself.
//! With one guest that is sound; with two, a guest switched in while idle sits in `wfi` waiting for
//! a deadline EL2 did not arm, and **the peer never runs again**. That reached `main` and made the
//! required boot gate time out (2 runs in 15 locally). `HCR_EL2.TWI` ([`trap_guest_wfi`]) turns
//! `wfi` into a voluntary yield, which closed the case that bit — but only behaviourally: it depends
//! on the guest choosing to execute `wfi`.
//!
//! ## ③-b2b-ii-e: EL2 gets a clock, and stops asking the guest for the CPU back
//!
//! **The guarantee above is now structural.** EL2 arms its own hypervisor timer (`CNTHP_*_EL2`,
//! [`gic::HYP_TIMER_INTID`]) for one slice on every switch-in and on every expiry, through the one
//! [`arm_slice`], and that expiry — not the guest's tick — is what preempts. Three things make it
//! unconditional, and each is a property some earlier rung bought:
//!
//! * the guest cannot **program** it — `CNTHP_*_EL2` is EL2-only, `UNDEFINED` at EL1;
//! * the guest cannot **mask** it — ③-b1 took the physical distributor away, so the kernel's
//!   `GICR_ISENABLER0` writes land in [`crate::vgic`] and touch no hardware, and a physical IRQ
//!   routed to EL2 by `HCR_EL2.IMO` (③-a2) is not maskable by EL1's `PSTATE.I`;
//! * the guest cannot **outlast** it — the deadline is absolute, so traps taken in between do not
//!   extend it and a guest that never traps reaches it at exactly the same instant as one that
//!   traps constantly.
//!
//! **What this removed is as much the rung as what it added.** `PREEMPT_EVERY` — preempt on every
//! eighth guest tick — is gone, and with it the arrangement where the GUEST's tick rate set the
//! scheduling quantum and a guest that stopped taking its tick stopped being preemptible. The
//! spinning-guest denial of service that reasoning left open (neither idle, so no `wfi`; no tick, so
//! no PPI 27) is closed by construction rather than by a workload that happens not to exhibit it.
//!
//! **What the boot itself cannot show, and the 2×2 that does.** Both guests here cooperate, so no
//! counter on a green boot distinguishes this rung from the one it replaces. The claim is made by
//! probe instead — `HCR_EL2.TWI` off *and* dom 1's tick forwarding cut a fifth of the way into its
//! boot, so nothing cooperative is left — against a control with EL2's clock disarmed and nothing
//! else changed. With the clock: dom 2 boots to userspace and powers off. Without it: **dom 2 never
//! executes an instruction.** The table, and what it corrected about `TWI`, is at
//! [`report_el2_slice`].
//!
//! Two consequences worth carrying, both of which had to be worked out before the code and not
//! after. A slice expiry arrives with a **different interrupt in hand** than a tick-driven
//! preemption did, so ③-b2b-ii-c1's "exactly one hardware-mapped list register in flight" does not
//! carry over and the invariant that rested on it is retired — see [`HW_RELEASED`]. And EL2 must now
//! complete an interrupt of **its own**: `CNTHP` is level-triggered, so the next deadline is armed
//! *before* the deactivate (or the GIC re-asserts immediately and storms EL2), and the deactivate
//! cannot be skipped (or EL2 gets exactly one slice for the whole boot, silently). See
//! [`gic::release_hyp_timer`] and [`report_el2_slice`].
//!
//! ## ③-b2b-ii-d: a guest reaches for its peer's memory and the hardware says no
//!
//! Each guest's device tree names an AMBA peripheral at the base of the OTHER guest's half, so the
//! kernel's bus scan reads its identification registers during boot and every read is refused. What
//! makes that a test rather than an anecdote is what EL2 checks at the moment of the fault
//! ([`handle_peer_fault`]): the address is unmapped in the faulting guest's image, resolves **to
//! itself** in the peer's live emitted image, and the peer's loaded kernel is sitting there. An
//! address that is merely unbacked would fault for a boring reason — and pointing the node at one
//! (probed) turns the refusal into a plain `LINUX GUEST TRAP` instead, which is how we know the
//! difference is being drawn.
//!
//! Both directions, and the guest **survives**: every marker after it is printed by a kernel that
//! took the abort and carried on, which is what separates a negative test from a crash.
//!
//! The headline is one string: **`[dom 2] baleen-guest-ram: 64000000-7fffffff:SystemRAM`**. It is
//! guest B's userspace reading guest B's `/proc/iomem`, which needs B's kernel to have parsed B's
//! DTB and reached that RAM through B's own Stage-2 — carrying EL2's tag and the guest's content in
//! one line, neither of which means much alone. Guest A cannot produce it: its window ends at
//! `0x63ffffff`, and the probe in [`switch_context`] shows what happens to a guest handed the wrong
//! image — an instruction abort on its first fetch.
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
use hv_core::sched::RunState;
use hv_core::{HvCall, Hypervisor};

use crate::abort::{self, DataAbort, EC_DATA_ABORT};
use crate::cell::BootCell;
use crate::console::GuestConsole;
use crate::ctx::CtxComponent;
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
/// The second domain. **It runs a second unmodified Linux kernel since ③-b2b-ii-c2** — it owns the
/// upper half of the guest-RAM window behind its own emitted Stage-2 image, drives its own emulated
/// PL011 and GICv3, and time-slices the one physical CPU with dom A through `hv-core`'s scheduler.
///
/// It got there a rung at a time: ③-b2a gave it an emitted image (and made the disjointness walk a
/// statement about a peer's *live* mapping rather than about unmapped space), ③-b2b-i built the
/// context switch and proved it carries a real kernel's state, ③-b2b-ii-a made every piece of
/// per-guest state an index, ③-b2b-ii-b put its blobs in its window, and ③-b2b-ii-c1 taught the one
/// physical timer to change hands.
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

/// Guest A's kernel `Image` load address — the base of guest RAM, per the arm64 boot protocol, and
/// what `ELR_EL2` is set to. Every other guest's is [`kernel_entry`].
const KERNEL_ENTRY: u64 = GUEST_RAM_BASE;
/// Guest A's flattened device tree (DTB) load address — handed to the kernel in `x0`.
const DTB_ADDR: u64 = 0x4b00_0000;
/// Guest A's initramfs load address — named in its DTB's `/chosen` `linux,initrd-*`.
///
/// **The kernel never learns this from us**, so before ③-b2b-ii-b hv-metal had no reason to know it
/// and did not. It is here because [`report_loaded_images`] reads the bytes at this address to
/// witness that the loader actually deposited a second guest's payload, and a witness that took the
/// address on faith would be checking a place instead of a thing.
const INITRD_ADDR: u64 = 0x4c00_0000;

/// The base of guest `slot`'s RAM window — the address its `Image` loads at and the base its DTB's
/// `/memory` node advertises. Derived from which model frames the guest owns, so it cannot disagree
/// with what the emitter maps for it.
const fn guest_ram_base(slot: usize) -> u64 {
    stage2::LINUX_RAM_BASE + first_frame(slot) as u64 * stage2::SUP_FRAME_BYTES
}

/// How far guest `slot`'s window sits above guest A's. **This is the whole of ③-b2b-ii-b's address
/// arithmetic**: the second kernel needed no new address agreed with anyone, because all three of
/// its blobs are guest A's plus this one delta — which is itself a consequence of the ③-b2a split,
/// not a new constant.
const fn window_delta(slot: usize) -> u64 {
    guest_ram_base(slot) - guest_ram_base(SLOT_A)
}

/// Guest `slot`'s kernel `Image` load address, i.e. where its `eret` enters.
const fn kernel_entry(slot: usize) -> u64 {
    KERNEL_ENTRY + window_delta(slot)
}
/// Guest `slot`'s DTB address, i.e. what its `x0` points at.
const fn dtb_addr(slot: usize) -> u64 {
    DTB_ADDR + window_delta(slot)
}
/// Guest `slot`'s initramfs address, i.e. what its DTB's `/chosen` names.
const fn initrd_addr(slot: usize) -> u64 {
    INITRD_ADDR + window_delta(slot)
}

/// **Every guest's three blobs must land inside that guest's own half of the window**, and the
/// kernel must not overrun the DTB sitting above it.
///
/// ③-b2a made the first half of this a `const assert!` for the RUNNING guest only, on the reasoning
/// that `KERNEL_ENTRY` is derived and safe while `DTB_ADDR` is a bare literal that a further split
/// could push into the peer's half — where the kernel would be handed a pointer its own Stage-2
/// cannot translate, and would die before its first console byte with nothing naming the cause.
/// ③-b2b-ii-b generalizes it to every guest, because there is now more than one to get wrong.
///
/// The `image_size` clause is new and was never checked anywhere: the DTB sits 48 MiB above the
/// kernel base and the shipped `Image` is 34.4 MiB, so a kernel that grew past that margin would
/// have the DTB written into the middle of itself. That is a runtime check ([`report_loaded_images`])
/// rather than a `const assert!`, because only the loaded image knows its own size.
const fn every_blob_is_inside_its_guest() -> bool {
    let mut slot = 0;
    while slot < NUM_GUESTS {
        let base = guest_ram_base(slot);
        let end = base + stage2::LINUX_SUP_FRAMES_PER_GUEST * stage2::SUP_FRAME_BYTES;
        if kernel_entry(slot) < base || kernel_entry(slot) >= end {
            return false;
        }
        if dtb_addr(slot) < base || dtb_addr(slot) >= end {
            return false;
        }
        if initrd_addr(slot) < base || initrd_addr(slot) >= end {
            return false;
        }
        slot += 1;
    }
    true
}
const _: () = assert!(
    every_blob_is_inside_its_guest(),
    "every guest's Image, DTB and initramfs must load inside that guest's own half of the window — \
     a blob in the peer's half is a pointer the guest's Stage-2 cannot translate"
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

/// Per-guest **software pending set** — the real-Linux path's answer to a full list-register bank.
///
/// ## ★ What this closes, and it is an ISOLATION defect rather than a robustness one
///
/// Before this, a guest SGI that found no free list register reached `crate::park()`. **A guest could
/// therefore halt the entire machine, peer domain included, in about six instructions**: mask
/// interrupts (`PSTATE.I=1`, so injected vINTs are never taken and never free their LR), then write
/// `ICC_SGI1R_EL1` five times with distinct SGI ids. Nothing between the trapped instruction and the
/// halt checked that the SGI was enabled, rate-limited it, or budgeted it per guest.
///
/// **Measured, not inferred** — a non-destructive probe on a real boot reported `bank=4 placed=4
/// fifth_injection_refused=true`, and that refusal is exactly the branch that parked.
///
/// It went unnoticed because the shipped Alpine guest issues 59 SGIs a boot and **takes them all**,
/// so the bank never holds more than one or two. The safety was a property of a cooperative workload
/// — design-lesson #127, in its most consequential instance so far.
///
/// A **set**, not a queue, for III-1's reason: a queue's "full" is the old halt relocated, while a set
/// over every INTID the distributor can name has no full state at all. See [`crate::pending`], which
/// is the one type both switches now share.
static LINUX_PENDING: [crate::pending::PendingSet; NUM_GUESTS] =
    [const { crate::pending::PendingSet::new() }; NUM_GUESTS];

/// vINTs that found no free list register and were recorded in the pending set instead.
static SGIS_DEFERRED: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// vINTs later drained from the pending set into a freed list register.
static SGIS_DRAINED: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// Maintenance interrupts ([`gic::MAINT_INTID`]) EL2 took on this path.
static MAINT_TAKEN: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// **Deliver a guest-generated SGI, or record it as pending if the bank is full.**
///
/// Total by construction: there is no failure to report, which is what removes the `park()` this
/// replaces. The two outcomes are "in a list register now" and "in the set until one frees".
fn deliver_or_defer_sgi(slot: usize, intid: u32) {
    if gic::inject(intid) {
        SGIS_DELIVERED[slot].fetch_add(1, Ordering::Relaxed);
        return;
    }
    if LINUX_PENDING[slot].mark(intid) {
        SGIS_DEFERRED[slot].fetch_add(1, Ordering::Relaxed);
        // Level-based, and armed only because something is now waiting — see
        // `gic::set_underflow_interrupt` for why arming it over an empty set livelocks EL2.
        gic::set_underflow_interrupt(true);
    }
    // `mark` refuses only an INTID the emulated distributor cannot name. A guest SGI comes from a
    // FOUR-BIT field (`gic::sgi1r_intid`), so it is at most 15 and this cannot happen; it is written
    // as a condition rather than an assert because a panic here would be the halt coming back.
}

/// **Drain `slot`'s pending set into free list registers, then re-arm `UIE` to match what is left.**
///
/// Runs from two places, for the two reasons III-1 identified:
/// * [`switch_context`] — on every switch-in, so a vCPU resumes with its bank as full as it can be.
///   Deterministic, needs no interrupt, and is the primary path.
/// * [`handle_linux_irq`] on [`gic::MAINT_INTID`] — for the case a switch cannot reach: a guest that
///   keeps running, taking and completing interrupts without exiting to EL2. There the bank runs down
///   while EL2 is not executing, and only the hardware's underflow signal can say so.
///
/// The trailing arm is a function of what REMAINS, which is what keeps the level-based `UIE` from
/// asserting over an empty set.
fn flush_pending_to_lrs(slot: usize) -> usize {
    let n = gic::num_list_registers();
    let mut placed = 0;
    for i in 0..n {
        if !gic::lr_is_free(gic::read_lr(i)) {
            continue;
        }
        match LINUX_PENDING[slot].take_next() {
            Some(intid) => {
                // Back through the raw allocator rather than writing the list register here, so the
                // set and the synchronous path place interrupts through exactly one encoder (#55).
                if gic::inject(intid) {
                    placed += 1;
                    SGIS_DRAINED[slot].fetch_add(1, Ordering::Relaxed);
                } else {
                    // Cannot happen single-CPU with a free LR just observed — but do not lose the
                    // vINT on a surprise.
                    let _ = LINUX_PENDING[slot].mark(intid);
                    break;
                }
            }
            None => break,
        }
    }
    gic::set_underflow_interrupt(!LINUX_PENDING[slot].is_empty());
    placed
}

/// The four INTIDs the overflow probe fills the bank with, and the fifth it then injects.
///
/// Nameable by the emulated distributor and **not** enabled by either guest, so even if one were
/// somehow observed it could not be presented. In practice none is: the probe runs between the
/// outgoing vCPU's `save` and the incoming one's `poison`, so every list register it writes is zeroed
/// before any guest runs again.
#[cfg(feature = "selftest")]
const PROBE_FILL_BASE: u32 = 200;
#[cfg(feature = "selftest")]
const PROBE_OVERFLOW_INTID: u32 = 204;

/// One-shot latch, so the probe perturbs exactly one switch out of the hundreds a boot makes.
#[cfg(feature = "selftest")]
static LR_OVERFLOW_PROBED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
/// `0` = not run, `1` = ran and every check held, `2` = ran and something did not.
#[cfg(feature = "selftest")]
static LR_OVERFLOW_RESULT: AtomicU64 = AtomicU64::new(0);
/// How many list registers the probe filled before the bank refused — the measured bank depth.
#[cfg(feature = "selftest")]
static LR_OVERFLOW_FILLED: AtomicU64 = AtomicU64::new(0);

/// **The discriminating probe: fill the bank, then inject one more.**
///
/// Without this the rung is unwitnessable. The shipped Alpine guest issues 59 SGIs a boot and takes
/// them all, so the bank never holds more than one or two: a "deferrals > 0" counter would read ZERO
/// on a good boot and prove nothing — the "WFI traps > 0" mistake this project already made once
/// (design-lesson #127). So the probe MANUFACTURES the condition instead of waiting for it.
///
/// **Safe by placement, not by care.** It runs between the outgoing vCPU's `save` and the incoming
/// one's `poison`: the bank has already been captured into `VCPU_CTX[cur]`, and every list register
/// is about to be zeroed and then overwritten by the incoming vCPU's restore. There is no window in
/// which a guest can observe anything this writes.
///
/// What it asserts, and each is a read-back rather than a count:
/// 1. the bank really does fill and refuse — the precondition of the old `park()`;
/// 2. the overflowing vINT lands in the pending set instead of halting;
/// 3. **`ICH_HCR_EL2.UIE` reads back ARMED** — the hardware agrees there is a refill pending;
/// 4. freeing one list register drains exactly that vINT;
/// 5. **`UIE` reads back CLEAR** — arming follows what remains, so an idle guest cannot be stormed.
#[cfg(feature = "selftest")]
fn probe_lr_overflow(slot: usize) {
    let n = gic::num_list_registers();
    for i in 0..n {
        gic::write_lr(i, 0);
    }
    let started_empty = LINUX_PENDING[slot].is_empty();

    let mut filled = 0;
    for k in 0..n {
        if gic::inject(PROBE_FILL_BASE + k as u32) {
            filled += 1;
        }
    }
    let bank_refuses = !gic::inject(PROBE_FILL_BASE + n as u32);

    deliver_or_defer_sgi(slot, PROBE_OVERFLOW_INTID);
    let deferred = !LINUX_PENDING[slot].is_empty();
    let armed = gic::underflow_interrupt_armed();

    gic::write_lr(0, 0);
    let placed = flush_pending_to_lrs(slot);
    let drained = LINUX_PENDING[slot].is_empty();
    let disarmed = !gic::underflow_interrupt_armed();

    for i in 0..n {
        gic::write_lr(i, 0);
    }

    let ok = started_empty
        && filled == n
        && bank_refuses
        && deferred
        && armed
        && placed == 1
        && drained
        && disarmed;
    LR_OVERFLOW_FILLED.store(filled as u64, Ordering::Relaxed);
    LR_OVERFLOW_RESULT.store(if ok { 1 } else { 2 }, Ordering::Relaxed);
}

/// Report what the pending set actually absorbed this boot.
///
/// ⚠ **Deliberately NOT a gate marker, and the reason is the whole lesson of design-lesson #127.**
/// A marker asserting a positive count would be a claim about the WORKLOAD and would redden on a
/// perfectly good boot; one asserting zero would redden on a boot that correctly survived a flood.
/// Neither is a property of the mechanism, so this line is a **diagnostic**, and `lroverflow` —
/// which manufactures the condition — is the assertion.
///
/// **What the numbers actually read, measured:** on a `real-linux` build every count is **zero**,
/// because Alpine takes all 59 of its SGIs and the bank never fills. On a `real-linux,selftest`
/// build — which is what the REQUIRED gate boots — the guest the probe ran on reads **1 deferred,
/// 1 drained**, because `probe_lr_overflow` manufactures exactly one overflow and then drains it.
/// That is the probe corroborating itself through a second, independent counter; it is not a guest
/// having flooded anything.
///
/// What it is for: if a guest ever does flood its bank, that stops being invisible. Before this rung
/// the machine simply stopped, and the last thing on the console was a halt message.
fn report_pending_absorption(uart: &mut Pl011) {
    for slot in 0..NUM_GUESTS {
        let deferred = SGIS_DEFERRED[slot].load(Ordering::Relaxed);
        let drained = SGIS_DRAINED[slot].load(Ordering::Relaxed);
        let maint = MAINT_TAKEN[slot].load(Ordering::Relaxed);
        let _ = writeln!(
            uart,
            "baleen: pending dom {}: {deferred} vINT(s) deferred when the list-register bank was \
             full, {drained} drained back into it, {maint} maintenance interrupt(s) taken (all zero \
             on a boot whose guest takes its own interrupts — this is a diagnostic, not a claim)",
            slot_dom(slot)
        );
    }
}

/// Report the overflow probe (`selftest` builds only).
#[cfg(feature = "selftest")]
fn report_lr_overflow(uart: &mut Pl011) {
    let filled = LR_OVERFLOW_FILLED.load(Ordering::Relaxed);
    match LR_OVERFLOW_RESULT.load(Ordering::Relaxed) {
        1 => {
            let _ = writeln!(
                uart,
                "baleen: lroverflow OK: a FULL list-register bank now DEFERS instead of halting — \
                 {filled} LRs filled and the next injection refused, the overflowing vINT went to \
                 the software pending set with ICH_HCR_EL2.UIE READ BACK as armed, and freeing one \
                 LR drained exactly it and read UIE back clear"
            );
        }
        2 => {
            let _ = writeln!(
                uart,
                "baleen: lroverflow FAIL: the overflow path did not behave as claimed ({filled} LRs \
                 filled) — a full bank may still halt, or UIE is not tracking the pending set"
            );
        }
        _ => {
            let _ = writeln!(
                uart,
                "baleen: lroverflow FAIL: the probe never ran — no switch occurred, so the claim \
                 that a full bank defers is UNWITNESSED on this boot"
            );
        }
    }
}

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
/// virtual interrupt deactivates the physical one, with no EL2 involvement. See the `HW`
/// note in [`crate::gic`].
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
    note_el2_entry();
    let intid = gic::ack_physical();
    // The interrupt belongs to whichever guest is executing: the physical timer's `CNTV_CVAL_EL0` is
    // part of the vCPU context, so the deadline that just expired is the running guest's own.
    let slot = current_slot();

    // ③-b2b-ii-e — **EL2's OWN clock, and the only interrupt here that no guest can influence.**
    // Checked before the guest's timer and before the mediation seam, because this one is not
    // mediated: `HYP_TIMER_INTID` is never offered to a vGIC, never forwarded, and never enabled or
    // disabled on a guest's behalf. A guest cannot mask it either — ③-b1 took the physical
    // distributor away, so the guest's `GICR_ISENABLER0` writes land in `crate::vgic` and touch no
    // hardware, and a physical IRQ routed to EL2 by `HCR_EL2.IMO` is not maskable by EL1's
    // `PSTATE.I`. That is what makes this rung structural rather than behavioural.
    if intid == gic::HYP_TIMER_INTID {
        // 1. **Arm the next deadline FIRST.** `CNTHP` is level-triggered; this is what clears
        //    `ISTATUS` and de-asserts the line, so the deactivate below cannot make the GIC
        //    re-assert immediately and storm EL2. See `arm_slice`.
        let _ = arm_slice();
        // 2. Priority drop (`EOImode=1`), so EL2's running priority returns to idle.
        gic::eoi_physical(intid);
        // 3. **EL2 completes its own interrupt**, and reads back that the controller agreed. With
        //    `EOImode=1` a missing `ICC_DIR_EL1` leaves this Active forever: EL2 would get exactly
        //    one slice for the whole boot and re-entry would be behavioural again, silently, with
        //    every other witness on this boot still green.
        SLICE_EXPIRIES.fetch_add(1, Ordering::Relaxed);
        if gic::release_hyp_timer() {
            SLICE_DEACTIVATED.fetch_add(1, Ordering::Relaxed);
        }
        // SAFETY: `frame` is the valid `*mut LinuxFrame` the trampoline just saved on the exception
        // stack, live until its epilogue reloads from it.
        preempt_through_the_scheduler(slot, unsafe { &mut *frame });
        return;
    }

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
        // ③-b2b-i made the tick the PREEMPTION POINT as well; **③-b2b-ii-e took that back**, and
        // taking it back is the rung. Preempting here meant the guest's own tick rate set the
        // quantum and a guest that stopped taking its tick stopped being preemptible — the
        // behavioural half of ledger item 9. EL2's slice expiry above is now the only thing that
        // preempts, so this path does exactly what ③-a2 built it for: forward the guest's tick.
        return;
    }

    // The GIC **maintenance interrupt** — III-1's refill signal, and on this path it is NEW.
    //
    // ⚠ **It is not optional, and adding the pending set without it would have relocated the halt
    // rather than removed it.** `gic::init_physical_vtimer` has always enabled this PPI here (its own
    // doc says the enable is "inert" on a path that never arms `UIE`), and until now nothing on the
    // Linux path ever armed `UIE` — so PPI 25 never fired, and if it had it would have fallen through
    // to the "no forwarding rule; halting" branch below. Arming `UIE` without this branch would have
    // turned a full-bank halt into a maintenance-interrupt halt.
    if intid == gic::MAINT_INTID {
        MAINT_TAKEN[slot].fetch_add(1, Ordering::Relaxed);
        // Drain FIRST: the interrupt is level-based on `UIE` + bank occupancy, and the drain is what
        // clears `UIE` when nothing is left. Deactivating before that could re-assert immediately.
        let _ = flush_pending_to_lrs(slot);
        gic::eoi_physical(intid);
        gic::deactivate_physical(intid);
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

/// **How often EL2's own clock takes the machine back** — the scheduling quantum, in hertz
/// (③-b2b-ii-e).
///
/// 100 Hz = a 10 ms slice. **Sized from measurement, not taste.** The shipped two-kernel boot spans
/// ~1.31 s of guest-visible time and made ~130 switches under ③-b2b-ii-c1's every-eighth-guest-tick
/// rule, so a 10 ms quantum lands the switch count in the same place: the timing profile the
/// `PREEMPT_EVERY` this replaces was protecting is preserved, while what *sets* the quantum stops
/// being the guest's tick rate and becomes a deadline EL2 owns.
///
/// The tick count is derived from `CNTFRQ_EL0` at run time rather than written here, because the
/// counter frequency is a platform property (62.5 MHz on this QEMU) and a hard-coded tick count
/// would silently become a different quantum on any other machine.
const EL2_SLICE_HZ: u64 = 100;

/// The slice length in counter ticks, computed once from `CNTFRQ_EL0`. Zero until [`arm_slice`] is
/// first called, which is also how [`report_el2_slice`] knows the clock was never started.
static SLICE_QUANTUM: AtomicU64 = AtomicU64::new(0);

/// `CNTPCT_EL0` at the FIRST arm — the origin the slice witness measures elapsed time from.
///
/// Not boot entry: everything before the first arm is EL2 setting the machine up with no guest
/// running, and counting it would charge the mechanism for time it did not own.
static SLICE_FIRST_ARM: AtomicU64 = AtomicU64::new(0);

/// How many times EL2's own timer expired and EL2 took the interrupt (③-b2b-ii-e).
static SLICE_EXPIRIES: AtomicU64 = AtomicU64::new(0);

/// How many of those the **redistributor confirmed** EL2 completed, Active → Inactive.
///
/// The other half, and the half a count of expiries structurally cannot see: EL2 runs `EOImode=1`,
/// so forgetting `ICC_DIR_EL1` leaves its own timer Active, the GIC never signals it again, and EL2
/// gets exactly one slice for the whole boot. See [`gic::release_hyp_timer`].
static SLICE_DEACTIVATED: AtomicU64 = AtomicU64::new(0);

/// `CNTHP_CTL_EL2` as read back after the most recent [`arm_slice`].
///
/// A register's own account of whether EL2's clock is armed, in the shape [`HCR_WITH_TWI`]
/// established: structural, true on every boot, and unsatisfiable by a lucky workload. Stored on
/// *every* arm rather than only the first, so it describes the steady state and not just the
/// cold start.
static CNTHP_CTL_READBACK: AtomicU64 = AtomicU64::new(0);

/// `CNTPCT_EL0` at the most recent entry to EL2 from a guest, of any cause.
static LAST_EL2_ENTRY: AtomicU64 = AtomicU64::new(0);

/// The longest interval, per guest, between two consecutive entries to EL2 — i.e. **the longest any
/// guest held the physical CPU** (③-b2b-ii-e).
///
/// **Reported, never asserted, and the distinction is the point.** This is the number the rung is
/// about, but a bound on it is not a valid gate: a cooperative guest keeps the interval far below
/// any quantum with EL2's clock switched off entirely, so the assertion would pass unchanged on
/// `main` (design-lesson #105). What discriminates is [`SLICE_EXPIRIES`] against elapsed time — a
/// quantity EL2's clock determines and no guest contributes to — and, properly, the probes.
///
/// Measured entry-to-entry, so it includes EL2's own service time for the previous trap; that is
/// microseconds against a 10 ms quantum and is stated rather than corrected for.
static MAX_HOLD: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// **Arm EL2's timer for one slice**, returning `CNTHP_CTL_EL2` read back after the write.
///
/// ## The one function, called from the cold start and from the steady state
///
/// Three callers — the last thing before the first `eret`, the first thing in the slice-expiry
/// handler, and the end of [`switch_context`] — and deliberately not three pieces of code
/// (design-lesson #130). The boot path is the resume path here in the same sense that guest B's
/// first instruction is executed by the same restore that resumes it: there is no arming code that
/// runs once and is never exercised again.
///
/// ## Arming is also how the level is dropped, and that ordering is load-bearing
///
/// `CNTHP` is level-triggered like any generic timer: its output is asserted while
/// `CNTPCT >= CNTHP_CVAL`. Writing the next deadline clears `ISTATUS` and de-asserts the line, which
/// is why the expiry handler arms **before** it completes the interrupt — deactivating under a high
/// level makes the GIC re-assert immediately and storm EL2. Same hazard ③-b2b-ii-c1 measured on the
/// guest's PPI 27; a different resolution only because EL2 can move its own deadline and cannot
/// move the guest's.
///
/// The deadline is absolute, so traps taken between arms do not extend it: a guest that traps a
/// thousand times still reaches its deadline at the same instant as one that traps never.
fn arm_slice() -> u64 {
    let quantum = {
        let q = SLICE_QUANTUM.load(Ordering::Relaxed);
        if q != 0 {
            q
        } else {
            let q = crate::time::frequency() / EL2_SLICE_HZ;
            SLICE_QUANTUM.store(q, Ordering::Relaxed);
            q
        }
    };
    let now = {
        use hv_hal::TimeSource;
        crate::time::GenericTimer.now()
    };
    let _ = SLICE_FIRST_ARM.compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed);
    let ctl: u64;
    // SAFETY: `CNTHP_CVAL_EL2`/`CNTHP_CTL_EL2` are the EL2 physical timer's own registers, RW at EL2
    // in a non-VHE hypervisor (probe-verified on this platform: see `gic::HYP_TIMER_INTID`). The
    // `isb` makes the write architecturally visible before the read-back, which is the witness.
    unsafe {
        asm!(
            "msr CNTHP_CVAL_EL2, {d}",
            "msr CNTHP_CTL_EL2, {e}",
            "isb",
            "mrs {c}, CNTHP_CTL_EL2",
            d = in(reg) now + quantum,
            e = in(reg) CNTHP_CTL_EL2_ENABLE,
            c = out(reg) ctl,
            options(nomem, nostack, preserves_flags),
        );
    }
    CNTHP_CTL_READBACK.store(ctl, Ordering::Relaxed);
    ctl
}

/// `CNTHP_CTL_EL2.ENABLE` (bit 0), with `IMASK` (bit 1) left clear so the timer actually signals.
const CNTHP_CTL_EL2_ENABLE: u64 = 1 << 0;
/// `CNTHP_CTL_EL2.IMASK` (bit 1) — set would mean armed but muted, which is the failure the
/// read-back witness is looking for.
const CNTHP_CTL_EL2_IMASK: u64 = 1 << 1;

/// Record that EL2 has just been entered from a guest, and charge the interval to whoever held the
/// pCPU (③-b2b-ii-e). Called first thing in both Linux-mode handlers, which between them are every
/// entry to EL2 on this path.
fn note_el2_entry() {
    let now = {
        use hv_hal::TimeSource;
        crate::time::GenericTimer.now()
    };
    let prev = LAST_EL2_ENTRY.swap(now, Ordering::Relaxed);
    if prev == 0 {
        return;
    }
    let slot = current_slot();
    let held = now.saturating_sub(prev);
    if held > MAX_HOLD[slot].load(Ordering::Relaxed) {
        MAX_HOLD[slot].store(held, Ordering::Relaxed);
    }
}

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

/// How many hardware-mapped list registers each guest has handed back at a switch (③-b2b-ii-c1).
///
/// **The witness is that this EQUALS [`TIMER_DEACTIVATED`]** — the software half of the handoff
/// against the controller's own account of the hardware half. Either is satisfiable with the other
/// deleted; together they are not.
///
/// ⚠ **③-b2b-ii-e retired the conjunct that used to sit beside it, and the reason is worth keeping.**
/// Under c1 a preemption was reached from [`handle_linux_irq`] having *just* forwarded a tick, so
/// exactly one `HW=1` list register existed at every preemption point and `released >= tick
/// handovers` was an invariant. A slice expiry arrives with a **different interrupt in hand**: the
/// guest may or may not still be holding an untaken forwarded tick, so `released` is 0 or 1
/// depending on the guest's timing. Both branches were traced before the mechanism changed —
/// untaken tick ⇒ non-free `HW=1` LR demoted *and* PPI 27 Active (EL2 having only priority-dropped);
/// already EOI'd ⇒ `lr_is_free` rejects the stale mapping *and* the guest's own EOI has already
/// deactivated the physical interrupt — and the equality holds on both. The lower bound does not,
/// and carrying it over would have refused a correct boot, which in this arc is the shape of every
/// witness that mentioned a count.
static HW_RELEASED: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// How many times the **interrupt controller agreed** that the forwarded timer went Active →
/// Inactive at a switch (③-b2b-ii-c1).
///
/// **The other half of the handoff, and the half [`HW_RELEASED`] structurally cannot see.** Demoting
/// a list register is EL2 editing bytes it saved itself: delete the physical deactivate entirely and
/// that count is unchanged, the boot stays green, and guest B hangs a rung later. This one is read
/// back from `GICR_ISACTIVER0` — the GIC's own view, and the Active state is precisely what would
/// stop a second guest being signalled the tick.
static TIMER_DEACTIVATED: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// How many times each guest has been switched **out** (③-b2b-ii-c2).
///
/// Distinct from [`SWITCHES`], which counts switch-*ins*, and the distinction only exists once there
/// are two runners: with A↔B alternating, a guest is switched out and back in almost but not exactly
/// the same number of times, and the timer handoff is an outgoing-side event. Comparing the two
/// would have been comparing different quantities — which is what the first version of
/// [`report_timer_handoff`] did, and it read `63 across 64 switches`.
static HANDOVERS: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

// ③-b2b-ii-e retired the `Handover` enum that used to sit here. It existed to condition the handoff
// invariant — a `Tick` handover was guaranteed to have a forwarded interrupt in flight, so
// `TICK_HANDOVERS` was a lower bound on demoted mappings. No handover class carries that guarantee
// any more (see `HW_RELEASED`), so both the counter and the discriminant are gone rather than kept
// as decoration: the three causes are already recoverable from `HANDOVERS`, `WFI_YIELDS` and the one
// `SYSTEM_OFF` each guest issues, and a parameter that no longer selects anything reads as though it
// does.

/// How many switch-ins found the live FP register file holding **someone else's** data
/// (③-b2b-ii-f) — i.e. how many times this guest would have read its peer's `v0..v31`.
///
/// **REPORTED, NEVER ASSERTED, and #127 is exactly why.** A boot whose guests never touch floating
/// point leaves this at zero and is a perfectly good boot; the number counts what the WORKLOAD did,
/// not what the mechanism guarantees. What it is worth reporting for is that it sizes the hole this
/// rung closed, from the live boot rather than from an argument: the same quantity read ~31 per boot
/// when it was measured with `CPTR_EL2.TFP` before the fix existed (see [`crate::fp`]).
static FP_FOREIGN: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// How many switch-ins were followed by a **read-back** confirming the live FP register file now
/// equals the incoming vCPU's saved one (③-b2b-ii-f).
///
/// **This is the assertable half, and it is structural: it must equal [`SWITCHES`] on every boot,
/// whatever the guests do.** Every restore is obliged to make the hardware match the context it
/// restored from — no guest behaviour can change that, so the equality is a property of the
/// mechanism in the sense #127 asks for.
///
/// It is not merely checking that `ldp` works. The bug class it catches is a **partial** restore —
/// a wrong offset dropping `v16..v31`, or `FPCR` written but not `FPSR` — which on any boot whose
/// guests happen not to use the high registers is byte-for-byte indistinguishable from a correct
/// one. The read-back is EL2 asking the register file what it actually holds, the same discipline
/// `TIMER_DEACTIVATED` applies to the redistributor and `verify_encoding` to the emitted image.
static FP_RESTORE_VERIFIED: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// How many times each guest has touched a PEER's memory and been refused by the hardware
/// (③-b2b-ii-d).
static PEER_FAULTS: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// How many peer faults EL2 will service for one guest before treating the guest as looping.
///
/// **This is a runaway backstop, not a bound on the probe, and the difference cost a near-miss.**
/// The first value here was 64, chosen from "the AMBA identification read is eight registers". The
/// boot actually produces **48 per guest** — the driver core re-probes, so the real number is eight
/// times however many times it retries, which is a function of probe ordering rather than anything
/// this file controls. 64 left a third of a margin against a quantity nobody was measuring; a
/// kernel that deferred once more would have turned the negative test into a `LINUX GUEST TRAP`.
///
/// So the cap is set where it can only catch what it is for: a guest looping on the access makes no
/// progress at all and blows past any figure of this size immediately, while a probe cannot
/// plausibly approach it. Same shape as the invariants earlier in this arc — do not pin a number to
/// a workload's behaviour when the mechanism does not depend on it.
const MAX_PEER_FAULTS: u64 = 4096;

/// Each guest's VMID-tagged `VTTBR_EL2`, as the proven emitter produced it (③-b2b-ii-c2).
///
/// Recorded at setup because a switch has to *install* the incoming domain's Stage-2, and the value
/// is the emitter's output rather than anything this file computes — `build_stage2_from_p2m` returns
/// it, and `report_disjointness` has already walked both images to the descriptors before either
/// guest runs. Plain atomics: written once before any guest exists, read from the IRQ handler.
static VTTBR: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// **③-b2b-i — preempt the running guest through `hv-core`'s REAL scheduler.**
///
/// **③-b2b-ii-e changed who calls this and why.** It used to be reached from the guest's own timer
/// tick, every eighth one (`PREEMPT_EVERY`) — so the guest's tick rate set the quantum, and a guest that
/// stopped taking its tick stopped being preemptible. It is now reached from EL2's own slice expiry
/// ([`gic::HYP_TIMER_INTID`]) and from nowhere else: the deadline belongs to EL2, so preemption no
/// longer depends on the guest doing anything at all.
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
    let dom = slot_dom(slot);

    // `try_borrow_mut`, and a skip rather than a halt if it is held: the cell is claimed during model
    // setup, and a slice expiry that lands there should defer, not kill a boot that is otherwise
    // fine. The witness counts switches actually performed, so a systematically-skipped switch shows
    // up as a count of zero rather than as silence. The expiry itself has already been completed and
    // the next deadline armed by the caller, so deferring costs one slice and nothing else.
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
    // `SchedPreempt`, not `SchedOffline`. The model already had the right transition and its doc
    // names this exact situation — *"the involuntary counterpart of a guest yield"*: `Running` →
    // `Runnable`, freeing the pCPU without retiring the vCPU. `guest.rs` uses `SchedOffline` because
    // its synthetic vCPUs genuinely finish; a kernel interrupted mid-instruction has not finished,
    // and offlining it left the model in `Offline`, from which `SchedRun` is refused (`WrongState`).
    // That refusal is the model declining to describe a lie, which is what it is for.
    sched_on(
        hv,
        dom,
        HvCall::SchedPreempt {
            vcpu: LINUX_VCPU,
            now,
        },
        "preempt the running vcpu",
    );

    let next = match next_runnable(hv, slot) {
        Some(n) => n,
        None => {
            let mut uart = crate::uart();
            let _ = writeln!(
                uart,
                "baleen: LINUX GUEST TRAP: no vcpu is Runnable after preempting dom {dom} — the \
                 model just made it Runnable, so this cannot happen; halting"
            );
            crate::park();
        }
    };
    sched_on(hv, slot_dom(next), scheduler_run(now), "run the next vcpu");
    drop(cell);

    switch_context(slot, next, frame);
}

/// Which guest's half of the RAM window contains `ipa`, if any (③-b2b-ii-d).
///
/// Derived from the same `first_frame`/`LINUX_SUP_FRAMES_PER_GUEST` split the model ownership and
/// the emitted images come from, so "whose memory is this" has one answer on this path and it is the
/// one the emitter used.
fn guest_owning(ipa: u64) -> Option<usize> {
    (0..NUM_GUESTS).find(|&slot| {
        let base = guest_ram_base(slot);
        (base..base + stage2::LINUX_SUP_FRAMES_PER_GUEST * stage2::SUP_FRAME_BYTES).contains(&ipa)
    })
}

/// **③-b2b-ii-d — a guest reached into its peer's memory, and the hardware said no.**
///
/// ## What makes this a test rather than an anecdote
///
/// An address that is simply not backed faults for a boring reason. This one is not: `ipa` is real
/// DRAM, owned in the model by the peer, mapped by the peer's **live** Stage-2 image, and — checked
/// here, from EL2, at the moment of the fault — actually holding the peer's loaded kernel. So the
/// three things that could each have made the refusal uninteresting are each ruled out by reading
/// them rather than by assuming them:
///
/// * **it resolves in the peer's image** — walked from the peer's emitted descriptors, so the frame
///   is not merely unmapped everywhere;
/// * **it resolves to itself** — the identity mapping the peer's DTB and the arm64 boot protocol
///   both require, so the peer really uses this address;
/// * **the bytes are there** — EL2 runs MMU-off and can read what the faulting guest cannot, and
///   what it finds at the peer's base is the `ARM\x64` header of a kernel that is currently running.
///
/// ## The guest SURVIVES, and that is deliberate
///
/// Skipping the faulting instruction leaves the guest's destination register holding whatever it
/// held before, which is exactly what a device that is not there would give it. The alternative —
/// killing the guest — would make the negative test indistinguishable from a crash, and would mean
/// the boot could never assert both that the access was refused *and* that everything else kept
/// working. Bounded by [`MAX_PEER_FAULTS`] so a guest that loops on it cannot spin EL2 forever.
fn handle_peer_fault(faulting: usize, owner: usize, ipa: u64, uart: &mut Pl011) {
    let n = PEER_FAULTS[faulting].fetch_add(1, Ordering::Relaxed) + 1;
    if n > MAX_PEER_FAULTS {
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: dom {} has faulted on dom {}'s memory {n} times (cap \
             {MAX_PEER_FAULTS}) — it is not probing, it is looping; halting",
            slot_dom(faulting),
            slot_dom(owner)
        );
        crate::park();
    }

    // Only the first one is reported in full: the AMBA identification read produces a fixed handful
    // of these, and eight identical paragraphs would bury the boot's other output.
    if n == 1 {
        let peer_l1 = hv_s2::arm64::vttbr_table(VTTBR[owner].load(Ordering::Relaxed));
        let mine_l1 = hv_s2::arm64::vttbr_table(VTTBR[faulting].load(Ordering::Relaxed));
        let in_peer = stage2::walk_stage2(peer_l1, ipa);
        let in_mine = stage2::walk_stage2(mine_l1, ipa);
        let identity = in_peer.map(|r| r.pa == ipa).unwrap_or(false);
        let magic = peek::u32_at(guest_ram_base(owner) + IMAGE_MAGIC_OFF);

        if in_mine.is_none() && identity && magic == IMAGE_MAGIC {
            let _ = writeln!(
                uart,
                "baleen: peerfault OK: dom {} touched dom {}'s memory at IPA 0x{ipa:08x} and the \
                 HARDWARE refused it — that address is unmapped in dom {}'s image, resolves to \
                 itself in dom {}'s live emitted image, and dom {}'s loaded kernel ('ARM\\x64') is \
                 sitting there right now; dom {} took the abort and kept running",
                slot_dom(faulting),
                slot_dom(owner),
                slot_dom(faulting),
                slot_dom(owner),
                slot_dom(owner),
                slot_dom(faulting)
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: peerfault FAIL: dom {} faulted at IPA 0x{ipa:08x}, but the refusal proves \
                 nothing — mapped in its own image: {}; resolves to itself in dom {}'s: {}; dom \
                 {}'s kernel magic there: 0x{magic:08x}",
                slot_dom(faulting),
                in_mine.is_some(),
                slot_dom(owner),
                identity,
                slot_dom(owner)
            );
            crate::park();
        }
    }

    // A data abort's preferred return is the FAULTING instruction.
    crate::guest::advance_elr_past_fault();
}

/// **Retire the guest that issued `SYSTEM_OFF` and hand the CPU to a peer** (③-b2b-ii-c2).
///
/// Returns `true` if a peer took it, `false` if that was the last guest standing and the machine has
/// nothing left to run.
///
/// **`SchedOffline`, and here it is the truthful transition** — the opposite of ③-b2b-i's finding
/// about preemption. A preempted kernel has not finished and offlining it would be the model
/// describing a lie; a kernel that has issued `SYSTEM_OFF` genuinely has, and `Offline` is exactly
/// what [`next_runnable`] then reads to stop dispatching it. One state change, and the selection
/// policy needs no separate record of who is dead.
///
/// The handover uses the **same** [`switch_context`] as a timer preemption, from the *synchronous*
/// trampoline's frame rather than the IRQ one. The two frames are the same layout and the two
/// trampolines the same save/restore discipline, so a switch out of an `HVC` is a switch — this path
/// does not get its own.
/// **Why a domain stopped being runnable** — EL2's record, because the MODEL cannot carry it.
///
/// `hv-core` has one state for both: `SchedOffline` makes a vCPU `Offline`, and that is correct —
/// "may this vCPU be dispatched" is the only question the scheduler is entitled to answer, and the
/// answer is the same either way. **But the boot transcript is not entitled to conflate them.**
/// Without this, `report_per_guest_state` would print *"dom N issued PSCI SYSTEM_OFF — a real Linux
/// kernel booted and shut down"* for a domain that was KILLED, which is a witness that lies about the
/// one thing the reader most needs to know.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Retirement {
    /// Still running, or never started.
    Live,
    /// Issued PSCI `SYSTEM_OFF` — a clean shutdown.
    PoweredOff,
    /// Did something EL2 has no rule for and was retired for it.
    Faulted,
}

/// Per-slot retirement reason. `u8` because it is written from trap handlers.
static RETIREMENT: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

fn set_retirement(slot: usize, why: Retirement) {
    RETIREMENT[slot].store(
        match why {
            Retirement::Live => 0,
            Retirement::PoweredOff => 1,
            Retirement::Faulted => 2,
        },
        Ordering::Relaxed,
    );
}

fn retirement_of(slot: usize) -> Retirement {
    match RETIREMENT[slot].load(Ordering::Relaxed) {
        1 => Retirement::PoweredOff,
        2 => Retirement::Faulted,
        _ => Retirement::Live,
    }
}

/// **Retire `cur` in the model and hand the pCPU to a runnable peer.** `false` = nobody is left.
///
/// The one derivation of retire-and-hand-over. `power_off_and_hand_over` and [`fault_retire`] are
/// both thin callers of it: a clean shutdown and a killed guest differ in the REASON recorded and in
/// what is printed, never in the mechanism, and two copies of a scheduler handover is exactly the
/// second-derivation defect this file has removed three times over.
fn retire_and_hand_over(
    cur: usize,
    frame: &mut LinuxFrame,
    uart: &mut Pl011,
    why: Retirement,
) -> bool {
    set_retirement(cur, why);
    let Some(mut cell) = crate::guest::GUEST_HV.try_borrow_mut() else {
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: dom {} retired while the model was borrowed; halting",
            slot_dom(cur)
        );
        crate::park();
    };
    let Some(hv) = cell.as_mut() else {
        crate::park();
    };
    let now = {
        use hv_hal::TimeSource;
        crate::time::GenericTimer.now()
    };
    sched_on(
        hv,
        slot_dom(cur),
        HvCall::SchedOffline {
            vcpu: LINUX_VCPU,
            now,
        },
        "retire the vcpu",
    );
    let Some(next) = next_runnable(hv, cur) else {
        return false;
    };
    sched_on(
        hv,
        slot_dom(next),
        scheduler_run(now),
        "run the surviving vcpu",
    );
    drop(cell);
    switch_context(cur, next, frame);
    true
}

/// **A guest did something EL2 has no rule for: retire THAT GUEST, not the machine.**
///
/// ## ★ Why every one of these used to halt, and why that stopped being right
///
/// Each call site below used to `crate::park()`. That was a defensible decision **when there was one
/// guest**: halting hurt only the guest that caused it, and a wrong guess about an undecodable access
/// is worse than a loud stop. **The second guest changed the meaning of every one of them without
/// changing a line of code** — a halt now takes down a peer that did nothing. That is the same shape
/// as honest-ledger item 9 (*"sound with one guest, FALSE with two"*).
///
/// And they are cheap to reach. Six of the seven are a **single instruction**: `ISV=0` is simply what
/// a load/store PAIR produces, so `stp x0, x1, [gic_base]` halted the hypervisor. The code said so
/// itself — *"None of them is reachable from the PL011 accesses a Linux driver actually makes"* —
/// which is a statement about a COOPERATIVE driver, not about a guest.
///
/// ## What replaces it
///
/// The offending domain is retired (`SchedOffline`, the same transition a clean `SYSTEM_OFF` uses,
/// because a killed domain likewise never runs again) and the pCPU goes to whoever is still
/// `Runnable`. Only when nobody is does the boot end.
///
/// ⚠ **The caller must `return` immediately after this.** Unlike the `park()` it replaces, this
/// function RETURNS, and the trampoline will `eret` into whichever guest is now current. Falling
/// through would resume the guest that just faulted — with its context already switched away.
fn fault_retire(cur: usize, frame: &mut LinuxFrame, uart: &mut Pl011, what: &str) {
    CONSOLE.borrow_mut().flush(cur, uart);
    let _ = writeln!(
        uart,
        "baleen: dom {} RETIRED — {what}. The domain is stopped; the machine is not.",
        slot_dom(cur)
    );
    if !retire_and_hand_over(cur, frame, uart, Retirement::Faulted) {
        end_of_boot(uart);
    }
}

/// Flush every console, print every witness, and leave QEMU cleanly.
///
/// Extracted from the PSCI `SYSTEM_OFF` arm so the fault path can end the boot the same way. One
/// derivation: a boot that ends because the last guest was RETIRED must report exactly what a boot
/// that ends because the last guest powered off reports, or the two endings would drift and only one
/// of them would be tested.
fn end_of_boot(uart: &mut Pl011) -> ! {
    let mut console = CONSOLE.borrow_mut();
    for slot in 0..NUM_GUESTS {
        console.flush(slot, uart);
    }
    drop(console);
    // FIRST, deliberately. Every `report_*` below can `park()` on a failed assertion, and the
    // retirement record is the one line that explains WHY a later report might legitimately fail —
    // printing it last meant a faulted boot lost the very fact that made sense of the failure.
    // (Found by the fault probe: `report_per_guest_state` parked on a retired domain's zero counter
    // before this line was ever reached.)
    report_retirements(uart);
    report_vpl011(uart);
    report_interrupt_mediation(uart);
    report_timer_handoff(uart);
    report_el2_slice(uart);
    report_wfi_yield(uart);
    report_fp_isolation(uart);
    report_pending_absorption(uart);
    #[cfg(feature = "selftest")]
    report_lr_overflow(uart);
    report_per_guest_state(uart);
    if (0..NUM_GUESTS).all(|s| retirement_of(s) == Retirement::PoweredOff) {
        let _ = writeln!(
            uart,
            "baleen: every real Linux guest has powered off — {NUM_GUESTS} unmodified \
             kernels ran isolated on hv-metal's EL2 and shut down (M5 Arc 5e)"
        );
    }
    semihosting_exit(); // clean QEMU exit (falls through to a fault→park if -semihosting off)
}

/// **Whether `slot`'s per-guest witnesses may be ASSERTED.**
///
/// A domain retired for a fault stopped part-way through its own boot, so the mechanisms it never
/// reached have correct zeros — its counters record HOW FAR IT GOT, not whether the hypervisor
/// works. Asserting them anyway is design-lesson #127 in its purest form, and the fault probe caught
/// three separate reports doing it (`perguest`, `vpl011`, `vsgi`), each of which parked or FAILED a
/// boot over a zero that was right.
///
/// **The shipped configuration is unaffected**: with both guests powering off cleanly this returns
/// `true` for every slot and every assertion runs exactly as before. The guard only ever fires on a
/// boot where a domain was killed — which, before this rung, could not happen at all.
fn witnesses_assertable(slot: usize) -> bool {
    retirement_of(slot) != Retirement::Faulted
}

/// How each domain's run ended — the line that keeps a retirement from reading as a shutdown.
fn report_retirements(uart: &mut Pl011) {
    for slot in 0..NUM_GUESTS {
        let dom = slot_dom(slot);
        match retirement_of(slot) {
            Retirement::PoweredOff => {
                let _ = writeln!(uart, "baleen: retire dom {dom}: powered off cleanly");
            }
            Retirement::Faulted => {
                let _ = writeln!(
                    uart,
                    "baleen: retire dom {dom}: RETIRED FOR A FAULT — it was stopped and the machine \
                     kept running"
                );
            }
            Retirement::Live => {
                let _ = writeln!(uart, "baleen: retire dom {dom}: never retired");
            }
        }
    }
}

fn power_off_and_hand_over(cur: usize, frame: &mut LinuxFrame, uart: &mut Pl011) -> bool {
    retire_and_hand_over(cur, frame, uart, Retirement::PoweredOff)
}

/// **Which guest gets the pCPU next** — round-robin from `cur` over the slots the MODEL says are
/// `Runnable` (③-b2b-ii-c2).
///
/// **Selection is asked of `hv-core` but decided here, and that split is the core's own.**
/// `hv_core::sched`'s module doc draws it explicitly: *"Mechanism, not policy … it does not decide
/// which runnable vCPU should get a CPU next. Fairness is policy, not a safety property."* So the
/// rotation is `hv-metal`'s, while *whether a vCPU may run at all* is read back from
/// [`hv_core::sched::System::state_of`] rather than from bookkeeping this file would otherwise have
/// to keep in step. A guest that has issued `SYSTEM_OFF` is `Offline` in the model, and that is the
/// one and only reason it stops being picked.
///
/// Stepping `1..=NUM_GUESTS` rather than `0..NUM_GUESTS` is what makes the peer preferred and the
/// caller the fallback: with one guest left alive the last candidate is `cur` itself, so the switch
/// degrades to ③-b2b-ii-c1's switch-to-self instead of having nowhere to go.
fn next_runnable(hv: &Hypervisor, cur: usize) -> Option<usize> {
    (1..=NUM_GUESTS)
        .map(|step| (cur + step) % NUM_GUESTS)
        .find(|&slot| hv.sched().state_of(slot_dom(slot), LINUX_VCPU) == Some(RunState::Runnable))
}

/// The `SchedRun` that dispatches a guest's vCPU onto the one physical CPU.
///
/// **It takes no slot, and that is the interesting part.** A vCPU id is scoped to its *domain* in
/// `hv_core::sched`, so every guest's single vCPU is [`LINUX_VCPU`] and every dispatch names
/// [`PCPU0`]; which guest is being run is carried entirely by the domain the call is dispatched on
/// behalf of ([`sched_on`]'s `dom`). A `slot` parameter here would look like it selected something.
fn scheduler_run(now: hv_hal::Ticks) -> HvCall {
    HvCall::SchedRun {
        vcpu: LINUX_VCPU,
        pcpu: PCPU0,
        now,
    }
}

/// Dispatch `call` on behalf of `dom`, halting loudly if the model refuses.
///
/// A refusal here is never a guest's fault and never recoverable: it means hv-metal asked for a
/// transition the model says is not legal from the state it is in, i.e. this file's idea of who is
/// running has come apart from the model's. Continuing would run a vCPU the scheduler does not
/// believe is on a CPU.
fn sched_on(hv: &mut Hypervisor, dom: DomId, call: HvCall, what: &str) {
    if let Err(e) = crate::teardown::dispatch(hv, dom, call) {
        let mut uart = crate::uart();
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: scheduler '{what}' refused for dom {dom}: {e:?}; halting"
        );
        crate::park();
    }
}

/// **Move the physical CPU from guest `cur` to guest `next`** — the register half of a switch, with
/// the scheduler transitions already made by the caller (③-b2b-ii-c1 / c2).
///
/// The ORDER of these steps is ③-b2b-ii-c1's rung and is documented at
/// [`gic::release_forwarded_timer`]; what ③-b2b-ii-c2 adds is that `next` may now differ from `cur`,
/// which turns two of them from identities into real work: the context restored is a different
/// vCPU's, and `VTTBR_EL2` becomes a different domain's VMID-tagged Stage-2. ③-b2b-ii-e adds an
/// eighth step, and it is the only one about the guest that is *arriving* rather than the one
/// leaving: its slice starts here.
fn switch_context(cur: usize, next: usize, frame: &mut LinuxFrame) {
    let mut ctx = VCPU_CTX.borrow_mut();
    // 1. Capture the outgoing vCPU, list registers and `CNTV_CVAL_EL0` included.
    ctx[cur].save(&frame.x);

    // 2. Demote its forwarded interrupts, and 3. hand the physical timer back. Between them these
    //    are the whole of Probe 0's fix: the outgoing guest keeps its pending tick as a purely
    //    VIRTUAL interrupt, and the one physical PPI on this machine stops being Active so it can be
    //    signalled to whoever runs next. See `gic::release_forwarded_timer` for the measurement that
    //    forced this and for why disable must precede deactivate.
    HANDOVERS[cur].fetch_add(1, Ordering::Relaxed);
    let released = ctx[cur].release_hardware_mappings();
    HW_RELEASED[cur].fetch_add(released, Ordering::Relaxed);
    if gic::release_forwarded_timer() {
        TIMER_DEACTIVATED[cur].fetch_add(1, Ordering::Relaxed);
    }

    // 3b. ③-b2b-ii-f — **whose data is in the FP register file right now?** `ctx[cur].fp()` was read
    //     off the hardware in step 1, so this compares the live file against what the INCOMING vCPU
    //     last owned. Different means the incoming guest was about to read its peer's `v0..v31` —
    //     which, before this rung, is exactly what it did. Taken here because step 4 is about to
    //     destroy the evidence.
    let incoming_fp = ctx[next].fp();
    if ctx[cur].fp() != incoming_fp {
        FP_FOREIGN[next].fetch_add(1, Ordering::Relaxed);
    }

    // 3c. The overflow probe, once per boot. Deliberately HERE: the outgoing bank is already saved
    //     and step 4 is about to zero every list register, so nothing it writes can be observed.
    #[cfg(feature = "selftest")]
    if !LR_OVERFLOW_PROBED.swap(true, Ordering::Relaxed) {
        probe_lr_overflow(cur);
    }

    // 4. Poison — see `crate::vcpu`. Still the instrument that stops a switch-to-self being vacuous.
    // SAFETY: at EL2 with the context saved, and the restore below is unconditional — the guest's
    // EL1 configuration is garbage only for the handful of instructions between the two.
    unsafe { ctx[next].poison() };

    // 5. Install the incoming vCPU. **Only now** does `CNTV_CTL_EL0`/`CNTV_CVAL_EL0` describe the
    //    guest about to run, which is why step 6 cannot be folded into step 3: re-arming the PPI
    //    while the outgoing guest's deadline was still loaded would fire the outgoing guest's timer
    //    into the incoming one.
    // SAFETY: at EL2, restoring the context of the vCPU about to be resumed. For guest B's FIRST
    // switch-in this is the arm64 boot protocol's entry state, seeded by `VcpuCtx::seed_boot` — so
    // B's boot and B's resume are the same instruction, not two paths that must agree.
    unsafe { ctx[next].restore(&mut frame.x) };
    drop(ctx);

    // 5b. Install the incoming DOMAIN's VMID-tagged Stage-2, with **no TLB flush** — M5 Arc 2's
    //     headline property, reached here by two REAL kernels for the first time. Distinct VMIDs are
    //     what make the two domains' TLB entries unable to alias, so the switch needs no `tlbi`; the
    //     images themselves were walked disjoint before either guest ran (`report_disjointness`).
    //
    //     **PROBED, and the probe is the isolation claim from the live side.** Installing guest A's
    //     image here instead of the incoming guest's makes guest B's very first instruction fetch
    //     fault: `EC=0x20 ELR=FAR=0x64000000 ESR=0x82000006` — an instruction abort, translation
    //     fault at level 2. A's map does not reach B's memory even to fetch one instruction, and a
    //     running guest is what says so, rather than a walk over the descriptors.
    crate::guest::set_vttbr_no_flush(VTTBR[next].load(Ordering::Relaxed));

    // 5c. ③-b2b-ii-f — read the FP file back off the hardware and confirm it is the incoming vCPU's.
    //     Structural: true on every switch regardless of what any guest does, which is what makes it
    //     assertable where `FP_FOREIGN` is not. Verifying here rather than immediately after step 5
    //     costs nothing: `set_vttbr_no_flush` touches no floating-point state.
    let mut live = crate::fp::FpCtx::ZERO;
    live.save();
    if live == incoming_fp {
        FP_RESTORE_VERIFIED[next].fetch_add(1, Ordering::Relaxed);
    }

    // 5d. Drain the incoming guest's pending set into its now-restored bank. It must run AFTER the
    //     restore (which overwrites the whole bank, so a pre-restore refill would be discarded), and
    //     it re-arms `UIE` for whatever is still pending — which is also what makes the arming follow
    //     the switched-IN vCPU rather than the outgoing one.
    let _ = flush_pending_to_lrs(next);

    // 6. Re-arm the physical PPI for the INCOMING guest, according to its own emulated distributor —
    //    the same mediation seam `handle_vgic_access` mirrors, applied at the other moment the
    //    answer can change. A guest running with its timer masked stays masked; one that wants it
    //    gets it, and gets it immediately, because its restored deadline has long since passed.
    let wants_timer = VGIC.borrow_mut()[next].is_enabled(gic::VTIMER_INTID);
    gic::set_ppi_enabled(gic::VTIMER_INTID, wants_timer);

    // 7. The pCPU now belongs to `next`, so every handler that asks "which guest?" must get the new
    //    answer from here on. Stored LAST: everything above still had to speak about `cur`.
    CURRENT.store(next, Ordering::Relaxed);
    SWITCHES[next].fetch_add(1, Ordering::Relaxed);

    // 8. ③-b2b-ii-e — the incoming guest gets a FULL slice, whichever of the three handovers got us
    //    here. On the slice-expiry path this re-arms a deadline the handler already set moments ago,
    //    which is deliberate: without it a guest entered by a `WFI` yield or a `SYSTEM_OFF` would
    //    inherit whatever was left of the yielding guest's slice, and the quantum would depend on
    //    who ran before you.
    let _ = arm_slice();
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
    note_el2_entry();
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

    // EC 0x01 = a trapped `WFI`/`WFE`. `HCR_EL2.TWI` makes an idle guest yield the pCPU instead of
    // freezing the machine — see `trap_guest_wfi`.
    if ec == EC_WFX && esr & 1 == 0 {
        // SAFETY: the trampoline gave us its on-stack frame; single-CPU, non-nested.
        handle_linux_wfi(unsafe { &mut *frame });
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
                let cur = current_slot();
                // This guest's last line is usually the one announcing the poweroff, and it arrives
                // without a terminating newline in front of this `HVC`. Flush before reporting, or
                // the witness swallows the last thing it said.
                CONSOLE.borrow_mut().flush(cur, &mut uart);
                let _ = writeln!(
                    uart,
                    "baleen: dom {} issued PSCI SYSTEM_OFF — a real Linux kernel booted and shut \
                     down on hv-metal's EL2",
                    slot_dom(cur)
                );
                // ③-b2b-ii-c2: one guest powering off is no longer the end of the machine. Retire
                // it in the MODEL and hand the physical CPU to whoever is still Runnable; only when
                // nothing is does the boot end.
                if power_off_and_hand_over(cur, frame, &mut uart) {
                    return;
                }
                end_of_boot(&mut uart);
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
        "baleen: guest FAULT: EC=0x{ec:02x} ELR=0x{elr:016x} FAR=0x{far:016x} ESR=0x{esr:08x}"
    );
    // SAFETY: the trampoline gave us its on-stack frame; single-CPU, non-nested.
    let frame = unsafe { &mut *frame };
    fault_retire(
        current_slot(),
        frame,
        &mut uart,
        "took an exception EL2 has no rule for",
    );
}

/// Route a guest **Stage-2 data abort** (`EC=0x24`) to one of four outcomes:
///
/// * the emulated **GIC**'s window (③-b1) — trap-and-emulated;
/// * the emulated **PL011**'s window (③-a1) — trap-and-emulated;
/// * a **peer guest's RAM** (③-b2b-ii-d) — the live negative test: recognised, checked against the
///   peer's live image, skipped, and the guest carries on ([`handle_peer_fault`]);
/// * anything else — a real fault in a guest that is supposed to have everything it touches either
///   mapped or emulated, reported with full syndrome and parked (the `LINUX GUEST TRAP` string the
///   gate forbids). **A fault inside the guest's OWN window lands here deliberately**: its image is
///   supposed to map every frame it owns, so a fault there means the emitter is wrong, which is a
///   different failure and must stay loud.
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

    // ③-b2b-ii-d — **THE LIVE NEGATIVE TEST.** A guest reaching into a PEER's half of the window is
    // not a bring-up fault: it is the thing this whole path exists to make impossible, arriving as
    // the hardware refusing it. Recognised here, before the catch-all below turns it into a
    // `LINUX GUEST TRAP` that the gate forbids.
    //
    // A fault inside the guest's OWN window deliberately falls through to that catch-all — its
    // Stage-2 image is supposed to map every frame it owns, so a fault there means the EMITTER is
    // wrong, which is a different failure and must stay loud.
    let faulting = current_slot();
    if let Some(owner) = guest_owning(ipa) {
        if owner != faulting {
            handle_peer_fault(faulting, owner, ipa, uart);
            return;
        }
    }

    if !vpl011::in_window(ipa) {
        let _ = writeln!(
            uart,
            "baleen: guest FAULT: EC=0x{ec:02x} data abort outside every emulated device — \
             IPA=0x{ipa:016x} ELR=0x{elr:016x} FAR=0x{far:016x} ESR=0x{esr:08x}",
            ec = EC_DATA_ABORT
        );
        fault_retire(
            faulting,
            frame,
            uart,
            "faulted outside every emulated device",
        );
        return;
    }

    // Three ways an access can be undecodable. Each is fatal rather than guessed at: emulating the
    // wrong register, or writing a result into the wrong guest register, is far worse than halting
    // with the syndrome on the console. None of them is reachable from the PL011 accesses a Linux
    // driver actually makes (single-register `readw`/`writew`/`readl`/`writeb` at aligned offsets),
    // which is exactly why a silent fallback would be untested code on a live path.
    if !a.isv || a.fnv || a.s1ptw {
        let _ = writeln!(
            uart,
            "baleen: guest FAULT: undecodable PL011 access at IPA=0x{ipa:016x} \
             (ISV={} FnV={} S1PTW={}) ESR=0x{esr:08x}",
            a.isv as u8, a.fnv as u8, a.s1ptw as u8
        );
        fault_retire(faulting, frame, uart, "made an undecodable PL011 access");
        return;
    }
    let offset = ipa - vpl011::VPL011_BASE;
    if !offset.is_multiple_of(a.access_bytes()) {
        let _ = writeln!(
            uart,
            "baleen: guest FAULT: misaligned PL011 access at IPA=0x{ipa:016x} ({} bytes)",
            a.access_bytes()
        );
        fault_retire(faulting, frame, uart, "made a misaligned PL011 access");
        return;
    }

    let slot = faulting;
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
            "baleen: guest FAULT: undecodable GIC access at IPA=0x{ipa:016x} \
             (ISV={} FnV={} S1PTW={}) ESR=0x{esr:08x}",
            a.isv as u8, a.fnv as u8, a.s1ptw as u8
        );
        fault_retire(
            current_slot(),
            frame,
            uart,
            "made an undecodable GIC access",
        );
        return;
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
            "baleen: guest FAULT: unmodelled {} register at offset 0x{:04x} \
             (IPA=0x{ipa:016x} {} {} bytes) ELR=0x{elr:016x} FAR=0x{far:016x} ESR=0x{esr:08x} \
            ",
            u.frame,
            u.offset,
            if a.wnr { "write" } else { "read" },
            a.access_bytes()
        );
        fault_retire(
            slot,
            frame,
            uart,
            "touched a register its distributor does not model",
        );
        return;
    }

    // A data abort's preferred return is the FAULTING instruction.
    crate::guest::advance_elr_past_fault();
}

/// `ESR_EL2.EC` for a **trapped MSR/MRS or System instruction** in AArch64 state.
const EC_SYSREG: u64 = 0x18;

/// `ESR_EL2.EC` for a **trapped `WFI`/`WFE`**; ISS bit 0 (`TI`) is 0 for `WFI`, 1 for `WFE`.
const EC_WFX: u64 = 0x01;
/// `HCR_EL2.TWI` (bit 13) — trap the guest's `WFI` to EL2.
const HCR_EL2_TWI: u64 = 1 << 13;

/// **Trap the guest's `WFI` (③-b2b-ii-c2 follow-up), because EL2 owns no clock of its own.**
///
/// Every re-entry to EL2 on this configuration is caused by the guest: a trap it takes, or the
/// arch-timer PPI it programmed for itself. With ONE guest that is sound — a kernel that goes idle
/// has, by construction, armed the timer it intends to be woken by, so EL2 comes back. With TWO it
/// is not, and the failure is total: a guest switched in while idle sits in `wfi` waiting for an
/// interrupt, EL2 gets no tick because the deadline it is waiting on is far away or absent, and the
/// **peer never runs again**. Both guests are frozen and the machine is dead.
///
/// That was not a theory. It reached `main` (③-b2b-ii-c2, #118) and made the post-merge
/// `real-linux boot (QEMU)` job time out; reproduced locally at **2 runs in 15**, both stopping
/// immediately after a guest printed `########## poweroff ##########` with no `SYSTEM_OFF` ever
/// arriving at EL2 — because the guest that owned the pCPU was not the one that had work to do.
///
/// `TWI` makes `wfi` a **voluntary yield**: the guest saying "I have nothing to do" becomes an exit
/// EL2 can act on. It is set here rather than in [`gic::enable_el2`] because that function is shared
/// with the synthetic path, which has one guest per phase and does not want the trap.
/// Returns `HCR_EL2` **read back after the write**, which is the witness: see [`report_wfi_yield`]
/// for why the trap cannot be witnessed by counting the traps it produces.
fn trap_guest_wfi() -> u64 {
    let hcr: u64;
    // SAFETY: `HCR_EL2` is an EL2 control register; the read-modify-write adds `TWI` and preserves
    // every other bit (`RW`, `VM`, `IMO`). `isb` so the trap is in force before the `eret`, and the
    // final read is the register's own account of what took effect.
    unsafe {
        asm!(
            "mrs {t}, hcr_el2",
            "orr {t}, {t}, {twi}",
            "msr hcr_el2, {t}",
            "isb",
            "mrs {t}, hcr_el2",
            t = out(reg) hcr,
            twi = in(reg) HCR_EL2_TWI,
            options(nomem, nostack, preserves_flags),
        );
    }
    hcr
}

/// `HCR_EL2` as read back after [`trap_guest_wfi`] wrote it.
static HCR_WITH_TWI: AtomicU64 = AtomicU64::new(0);

/// Wait at EL2 for the physical interrupt the guest was waiting for.
///
/// Reached when a guest goes idle and **no peer is runnable** — there is nothing to switch to, so
/// EL2 waits instead of returning to a guest that would immediately trap again (which would be a
/// livelock, not a wait). `wfi` wakes on a pending physical interrupt regardless of `PSTATE.I`, so
/// the guest's own arch-timer PPI brings EL2 back, and the `eret` then delivers it.
///
/// **③-b2b-ii-e bounded this wait.** It used to end only when a GUEST's deadline arrived — the same
/// dependence ledger item 9 is about, in the one place EL2 was already awake for it. EL2's slice is
/// armed across the wait, so `CNTHP` wakes it after at most one quantum whether or not any guest's
/// timer ever fires. Nothing else here changes: with no peer runnable there is still nothing to
/// switch to, and the wake costs one switch-to-self.
fn wait_at_el2() {
    // SAFETY: `wfi` is an unprivileged hint with no memory or register effect.
    unsafe { asm!("wfi", options(nomem, nostack, preserves_flags)) };
}

/// How many `WFI`s each guest has yielded to EL2 on (③-b2b-ii-c2 follow-up).
static WFI_TRAPS: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];
/// How many of those handed the pCPU to a peer that had work to do.
static WFI_YIELDS: [AtomicU64; NUM_GUESTS] = [const { AtomicU64::new(0) }; NUM_GUESTS];

/// **A guest went idle — give the pCPU to someone who can use it.**
///
/// The whole point of trapping `wfi`: see [`trap_guest_wfi`] for what happens without this.
///
/// [`next_runnable`] is consulted **before** `SchedPreempt`, and that is deliberate — while this
/// guest is still `Running` the model reports it as such, so the only slot that can come back is a
/// genuine *peer*. (The preemption path calls it after, where falling back to self is what it
/// wants.) `None` therefore means "nobody else can use the CPU", and the honest answer to that is to
/// wait, not to hand it back to a guest that has just said it has nothing to do.
fn handle_linux_wfi(frame: &mut LinuxFrame) {
    let cur = current_slot();
    WFI_TRAPS[cur].fetch_add(1, Ordering::Relaxed);

    // A trapped `WFI`'s preferred return is the `WFI` ITSELF. Advance FIRST: this edits the live
    // `ELR_EL2`, which still belongs to the OUTGOING guest — doing it after the switch would move
    // the *incoming* guest's resume point by one instruction.
    crate::guest::advance_elr_past_fault();

    let Some(mut cell) = crate::guest::GUEST_HV.try_borrow_mut() else {
        wait_at_el2();
        return;
    };
    let Some(hv) = cell.as_mut() else {
        wait_at_el2();
        return;
    };
    let Some(peer) = next_runnable(hv, cur) else {
        drop(cell);
        wait_at_el2();
        return;
    };
    let now = {
        use hv_hal::TimeSource;
        crate::time::GenericTimer.now()
    };
    sched_on(
        hv,
        slot_dom(cur),
        HvCall::SchedPreempt {
            vcpu: LINUX_VCPU,
            now,
        },
        "preempt an idle vcpu",
    );
    sched_on(
        hv,
        slot_dom(peer),
        scheduler_run(now),
        "run the peer an idle vcpu yielded to",
    );
    drop(cell);
    WFI_YIELDS[cur].fetch_add(1, Ordering::Relaxed);
    switch_context(cur, peer, frame);
}

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
        // ★ This used to `park()` when the bank was full — a halt a guest could REACH, taking the
        //   peer domain with it. Delivery is now total: see `deliver_or_defer_sgi` and
        //   `LINUX_PENDING`. There is no `false` left to branch on, which is what makes the halt
        //   unwritable rather than merely unwritten.
        deliver_or_defer_sgi(current_slot(), intid);
        // A trapped instruction's preferred return is the instruction ITSELF; resume past it or the
        // guest re-executes the `msr` forever.
        crate::guest::advance_elr_past_fault();
        return;
    }

    let _ = writeln!(
        uart,
        "baleen: guest FAULT: unhandled system-register access (Op0={} Op1={} CRn={} CRm={} \
         Op2={} {}) ELR=0x{elr:016x} FAR=0x{far:016x} ESR=0x{esr:08x}",
        (iss >> 20) & 0x3,
        (iss >> 14) & 0x7,
        (iss >> 10) & 0xf,
        (iss >> 1) & 0xf,
        (iss >> 17) & 0x7,
        if iss & 1 == 0 { "write" } else { "read" },
    );
    fault_retire(
        current_slot(),
        frame,
        uart,
        "accessed a system register EL2 has no rule for",
    );
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
    for slot in 0..NUM_GUESTS {
        // A retired domain's witnesses are not assertable — see `witnesses_assertable`.
        if !witnesses_assertable(slot) {
            continue;
        }
        let dom = slot_dom(slot);
        let (ok, traps, dr_writes) = VPL011.borrow_mut()[slot].witness();
        if ok {
            let _ = writeln!(
                uart,
                "baleen: vpl011 OK: dom {dom}'s console is EMULATED — its own userspace's \
                 'BALEEN-STEP0-OK' was written to dom {dom}'s emulated PL011 DR register in EL2 \
                 ({traps} register traps, {dr_writes} bytes relayed to the real PL011)"
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: vpl011 FAIL: dom {dom}'s console did not go through its emulator \
                 ({traps} register traps, {dr_writes} bytes forwarded) — the PL011 is being passed \
                 through, the transmit path is broken, or this guest never reached userspace"
            );
        }
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
    for slot in 0..NUM_GUESTS {
        // A retired domain's witnesses are not assertable — see `witnesses_assertable`.
        if !witnesses_assertable(slot) {
            continue;
        }
        let dom = slot_dom(slot);
        let n = TIMER_FORWARDED[slot].load(Ordering::Relaxed);
        if n > 0 {
            let _ = writeln!(
                uart,
                "baleen: vtimer OK: dom {dom}'s scheduler tick is FORWARDED — {n} physical timer \
                 interrupts (INTID {}) taken at EL2 under HCR_EL2.IMO=1 while dom {dom} held the \
                 pCPU, and injected as hardware-mapped virtual interrupts",
                gic::VTIMER_INTID
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: vtimer FAIL: EL2 forwarded no timer interrupt to dom {dom} — it is taking \
                 the PPI directly (IMO=0), the physical CPU interface never delivered one, or this \
                 guest never ran"
            );
        }

        let (gic_traps, gic_enables) = VGIC.borrow_mut()[slot].witness();
        if gic_traps > 0 && gic_enables > 0 {
            let _ = writeln!(
                uart,
                // "enable TRANSITIONS", not "INTIDs enabled": `vgic.rs` counts every write that
                // newly enables an INTID, so an INTID enabled, disabled and re-enabled counts twice.
                // Measured on the shipped boot: 11 transitions against 10 INTIDs actually enabled.
                // The number is a genuine mechanism witness; the sentence used to name a different
                // quantity from the one it printed.
                "baleen: vgic OK: dom {dom}'s interrupt controller is EMULATED — {gic_traps} \
                 GICD/GICR register traps in EL2, {gic_enables} INTID enable transitions through a \
                 distributor that is dom {dom}'s alone and that no guest can reach (Stage-2 device \
                 pass-through window: 0 bytes)"
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: vgic FAIL: dom {dom}'s GIC accesses did not go through its emulator \
                 ({gic_traps} traps, {gic_enables} enables) — the distributor is being passed \
                 through, or this guest never ran"
            );
        }

        let switches = SWITCHES[slot].load(Ordering::Relaxed);
        if switches > 0 {
            let _ = writeln!(
                uart,
                "baleen: vcpu OK: dom {dom} was dispatched onto the pCPU {switches} times through \
                 hv-core's scheduler — {} context registers plus the vGIC bank (list registers + \
                 ICH_VMCR_EL2) reinstated each time, with every one of them poisoned in between",
                vcpu::CtxReg::ALL.len()
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: vcpu FAIL: dom {dom} was never dispatched — the timer tick did not reach \
                 the switch, so nothing here was exercised for this guest"
            );
        }

        let sgis = SGIS_DELIVERED[slot].load(Ordering::Relaxed);
        if sgis > 0 {
            let _ = writeln!(
                uart,
                "baleen: vsgi OK: {sgis} of dom {dom}'s SGIs MEDIATED at EL2 — ICC_SGI1R_EL1 \
                 writes trap under HCR_EL2.IMO=1 and are delivered as virtual interrupts"
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: vsgi FAIL: EL2 mediated no SGI for dom {dom} — it reached its own SGI \
                 generation register, which HCR_EL2.IMO=1 is supposed to make impossible"
            );
        }
    }
}

// ─── ③-b2b-ii-b: what the loader actually deposited ──────────────────────────────────────────────

/// arm64 `Image` header, from `Documentation/arch/arm64/booting.rst`: `image_size` at +16, `flags`
/// at +24, and the `ARM\x64` magic at +56.
const IMAGE_SIZE_OFF: u64 = 16;
const IMAGE_FLAGS_OFF: u64 = 24;
const IMAGE_MAGIC_OFF: u64 = 56;
/// `"ARM\x64"` as the little-endian `u32` the header stores.
const IMAGE_MAGIC: u32 = 0x644d_5241;
/// `flags` bit 3: **1 = the 2 MiB-aligned base may be ANYWHERE in physical memory.**
///
/// **This is the single fact the whole arc rests on.** The second kernel needs no second build only
/// because the shipped `Image` is fully relocatable, so the same file boots at `0x6400_0000`. That
/// was measured off the header rather than assumed — and asserting it here means an Alpine bump that
/// silently lost the property fails at this line, naming it, instead of hanging guest B at its first
/// instruction with nothing to go on.
const IMAGE_FLAG_RELOCATABLE: u64 = 1 << 3;
/// The flattened-device-tree magic, stored big-endian at offset 0.
const DTB_MAGIC: u32 = 0xd00d_feed;
/// gzip's `1f 8b`, as the little-endian `u16` a read at the initramfs base returns.
const GZIP_MAGIC: u16 = 0x8b1f;

/// Read a `u16`/`u32`/`u64` of **physical** memory from EL2.
///
/// Safe functions, not `unsafe` ones, and the reason is the same argument `crate::pl011` makes for
/// its MMIO: the precondition is a property of *this* configuration, not of the caller. EL2 runs
/// MMU-off and identity-mapped throughout, and every caller here reads inside the guest-RAM window —
/// bounded above by [`every_blob_is_inside_its_guest`] at compile time and by xtask's loader guard
/// against the `-m` size. A `pa` outside DRAM would be the bug, and no caller can name one.
mod peek {
    pub(super) fn u16_at(pa: u64) -> u16 {
        // SAFETY: an identity-mapped DRAM address inside the guest-RAM window (see the module
        // docs). Read-only, volatile, and aliasing no Rust memory — the window is loader-owned
        // bytes, never a Rust allocation.
        unsafe { core::ptr::read_volatile(pa as *const u16) }
    }
    pub(super) fn u32_at(pa: u64) -> u32 {
        // SAFETY: as [`u16_at`]; the address is 4-byte aligned at every call site (header offsets
        // 0 and 56 off a 2 MiB-aligned base).
        unsafe { core::ptr::read_volatile(pa as *const u32) }
    }
    pub(super) fn u64_at(pa: u64) -> u64 {
        // SAFETY: as [`u16_at`]; the address is 8-byte aligned at every call site (header offsets
        // 16 and 24 off a 2 MiB-aligned base).
        unsafe { core::ptr::read_volatile(pa as *const u64) }
    }
}

/// **③-b2b-ii-b's witness: every guest's window really holds a loaded, bootable payload.**
///
/// **Why this is not decoration.** Guest B's blobs are deposited by three `-device loader` entries
/// in a crate that cannot depend on `hv-metal`, at addresses agreed only by arithmetic on both
/// sides. Nothing in the existing gate can see them: B does not run, so a boot in which QEMU wrote
/// B's `Image` to the wrong address, or did not write it at all, is byte-for-byte the boot in which
/// it did. The first symptom would arrive a whole rung later, as guest B executing whatever happens
/// to be at `0x6400_0000` — which is zeroes, i.e. a hang with no cause on the console.
///
/// So EL2 reads the bytes. The `ARM\x64` magic, the DTB's `d00dfeed` and gzip's `1f 8b` are there
/// only because the loader put them there; they cannot be produced by hv-metal, by the emitter, or
/// by guest A.
///
/// **It checks BOTH guests, and that is what makes it self-instrumenting.** Guest A's payload is
/// known-good — it boots on every run of this gate — so A's line passing while B's fails says the
/// check is right and the load is wrong, which is the one thing a peer-only check could not tell
/// you (design-lesson #118).
///
/// It also lands three assertions nothing made before: that the image is **relocatable**
/// ([`IMAGE_FLAG_RELOCATABLE`]), that `image_size` is non-zero, and that the kernel does not overrun
/// the **DTB** sitting 48 MiB above it — a margin the shipped 34.4 MiB `Image` fits with room to
/// spare, and which nothing would have noticed it outgrowing.
fn report_loaded_images(uart: &mut Pl011) {
    for slot in 0..NUM_GUESTS {
        let (dom, kernel, dtb, initrd) = (
            slot_dom(slot),
            kernel_entry(slot),
            dtb_addr(slot),
            initrd_addr(slot),
        );
        let magic = peek::u32_at(kernel + IMAGE_MAGIC_OFF);
        let size = peek::u64_at(kernel + IMAGE_SIZE_OFF);
        let flags = peek::u64_at(kernel + IMAGE_FLAGS_OFF);
        let dtb_magic = u32::from_be(peek::u32_at(dtb));
        let gzip = peek::u16_at(initrd);

        let bad = if magic != IMAGE_MAGIC {
            Some("the Image magic 'ARM\\x64' is absent — no kernel was loaded at this address")
        } else if size == 0 {
            Some("the Image header reports a zero image_size")
        } else if flags & IMAGE_FLAG_RELOCATABLE == 0 {
            Some(
                "the Image is NOT relocatable (flags bit 3 clear) — this build boots the same file \
                 at two different bases, which only a relocatable kernel permits",
            )
        } else if kernel + size > dtb {
            Some("the Image overruns the DTB loaded above it")
        } else if dtb_magic != DTB_MAGIC {
            Some("the DTB magic 0xd00dfeed is absent — no device tree was loaded at this address")
        } else if gzip != GZIP_MAGIC {
            Some("the initramfs gzip magic 0x1f8b is absent — no initramfs was loaded here")
        } else {
            None
        };

        match bad {
            None => {
                let _ = writeln!(
                    uart,
                    "baleen: guestimage OK: dom {dom} — Image 'ARM\\x64' {} MiB, relocatable, at \
                     0x{kernel:08x}; DTB 0xd00dfeed at 0x{dtb:08x}; gzip initramfs at \
                     0x{initrd:08x} (read from EL2 before any guest ran)",
                    size / (1024 * 1024)
                );
            }
            Some(why) => {
                let _ = writeln!(
                    uart,
                    "baleen: guestimage FAIL: dom {dom} at 0x{kernel:08x}: {why} (Image magic \
                     0x{magic:08x}, size 0x{size:x}, flags 0x{flags:x}, DTB magic \
                     0x{dtb_magic:08x}, initramfs magic 0x{gzip:04x})"
                );
                crate::park();
            }
        }
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

/// **③-b2b-ii-c1's witness: the one physical timer changes hands at every switch.**
///
/// **What the boot could not tell you without this.** ③-b2b-ii-c1 is a rung whose entire content is
/// that a physical interrupt stops being Active at a moment nothing observes — the guest that
/// resumes is the guest that left, so it boots identically whether the handoff happened or not.
/// Every other marker in the gate is satisfied either way. That is the same trap ③-b2b-i's
/// switch-to-self fell into, arriving one rung later at a different mechanism.
///
/// **The claim is an equality, not a tally** — but ③-b2b-ii-e changed WHICH equality, and that
/// change is the one thing to read carefully here. Under c1 the preemption point was reached from
/// [`handle_linux_irq`] having *just* forwarded the timer, so exactly one hardware-mapped list
/// register existed at every switch and the count of demotions was pinned to the count of switches.
/// A slice expiry arrives with a **different interrupt in hand** and no such guarantee: 0 or 1
/// depending on whether the guest has already EOI'd its tick. What survives — and what was always
/// the load-bearing half — is that the SOFTWARE demotion and the CONTROLLER-confirmed deactivation
/// agree with each other, on both branches. See [`HW_RELEASED`] for the branch-by-branch trace.
///
/// **The antecedent got RARE at ③-b2b-ii-e, and the kill probe was re-run rather than assumed.**
/// A guest now leaves the pCPU at an arbitrary instruction rather than moments after EL2 forwarded
/// it a tick, so "still holding an untaken forwarded tick" fell from *every* switch to **1 per guest
/// per boot** (measured; a ~1.5% window — Linux's GIC handler against a ~1.25 ms tick period). The
/// tempting conclusion is that the mechanism stopped mattering. **It has not: deleting the physical
/// deactivate still kills the boot.** Re-run on this rung, both guests reach userspace, print
/// `########## poweroff ##########`, and then neither completes `SYSTEM_OFF` — one missed
/// deactivation leaves PPI 27 Active for good, and no guest gets another tick.
///
/// What DID change is the shape of the failure, and it is worth one line: under c1 that was a frozen
/// machine, because the guest's tick was the only thing that re-entered EL2. Now EL2 keeps its own
/// clock, keeps taking slices and keeps switching — the hypervisor survives its own bug, and the
/// guests are what stop. Still fatal to the gate, and diagnosable instead of silent.
///
/// **Honest limit.** This says the *outgoing* half happened: whenever a mapping was in flight it was
/// demoted and the physical interrupt released. It cannot witness the *incoming* half — that a
/// different guest is then signalled the timer — which is what the kill probe above is for.
fn report_timer_handoff(uart: &mut Pl011) {
    for slot in 0..NUM_GUESTS {
        let dom = slot_dom(slot);
        let released = HW_RELEASED[slot].load(Ordering::Relaxed);
        let deactivated = TIMER_DEACTIVATED[slot].load(Ordering::Relaxed);
        let handovers = HANDOVERS[slot].load(Ordering::Relaxed);

        // The two conjuncts that survive ③-b2b-ii-e, and what was removed:
        //
        // * `released == deactivated` — **the load-bearing one, unchanged.** It cross-checks the
        //   SOFTWARE half (EL2 demoted the mapping in the context it saved) against the HARDWARE
        //   half (the redistributor agreed the physical interrupt went Inactive). Either alone is
        //   satisfiable with the other deleted; together they are not, and both branches of a slice
        //   expiry satisfy it — see `HW_RELEASED`.
        // * `released <= handovers` — nothing was demoted outside a handover.
        //
        // RETIRED: `released >= tick-driven handovers`. It rested on every preemption being reached
        // from `handle_linux_irq` with a freshly forwarded interrupt in flight, which is exactly the
        // property ③-b2b-ii-e removed. Carrying it over would have refused a correct boot — the
        // fifth time in this arc that an invariant mentioning a count turned out to be a claim about
        // the workload. Nothing replaces it as a FLOOR here: that job moved to `report_el2_slice`,
        // where the quantity is elapsed time against a deadline EL2 owns and no guest contributes to.
        //
        // Also deliberately NOT asserted, and it was already true before this rung: `released ==
        // handovers`. A guest can leave the pCPU with nothing in flight — after `SYSTEM_OFF`, after
        // a `WFI`, or at a slice boundary that lands between its EOI and its next tick — so the
        // count depends on the guest's timing, not on the mechanism. Three earlier forms of this
        // witness (`== switches`, `== tick handovers`, `>= tick handovers`) each refused, or would
        // have refused, a perfectly correct boot.
        let ok = released == deactivated && released <= handovers;
        if ok {
            let _ = writeln!(
                uart,
                "baleen: handoff OK: dom {dom} gave the forwarded timer up every time it left the \
                 pCPU holding one — {released} hardware-mapped list registers demoted and {} \
                 controller-confirmed Active -> Inactive transitions of PPI {}, across {handovers} \
                 handovers; then re-armed from the incoming guest's own emulated distributor",
                deactivated,
                gic::VTIMER_INTID
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: handoff FAIL: dom {dom} demoted {released} hardware-mapped list registers \
                 but the redistributor confirmed {deactivated} deactivations, across {handovers} \
                 handovers — the two halves of the handoff disagree, or a mapping was demoted \
                 outside a handover. The physical timer then stays Active across a switch and the \
                 next guest can never be signalled it"
            );
            crate::park();
        }
    }
}

/// **The witness for the `WFI` yield**, and it is a READ-BACK rather than a count.
///
/// **The obvious witness is wrong, and it was wrong in the shape this arc keeps hitting.** Counting
/// trapped `WFI`s asserts something about the GUESTS' timing, not about the mechanism: with two
/// kernels sharing one pCPU each is permanently behind on work, so a boot in which neither ever goes
/// idle is a perfectly good boot with a count of zero. Measured — a run of this gate produced
/// exactly that, and an earlier version of this function refused it.
///
/// So the assertion is the STRUCTURAL half: `HCR_EL2` read back after the write, showing `TWI`
/// really took effect. That is true on every boot and cannot be satisfied by luck. The counts are
/// reported beside it as the behavioural half, and deliberately NOT asserted.
///
/// **③-b2b-ii-e DEMOTED this mechanism, and saying so is the point of keeping the marker.** Until
/// rung e, `TWI` was the *only* thing standing between an idle guest and a frozen machine — the
/// residue this doc used to declare. EL2 now owns a clock ([`report_el2_slice`]), so re-entry no
/// longer depends on a guest choosing to execute `wfi` at all, and `TWI` becomes an **efficiency**
/// mechanism: without it an idle guest burns its whole 10 ms slice doing nothing while its peer
/// waits. That is a real cost and the trap stays, but it is no longer load-bearing for liveness, and
/// this marker should not be read as though it were.
fn report_wfi_yield(uart: &mut Pl011) {
    let hcr = HCR_WITH_TWI.load(Ordering::Relaxed);
    if hcr & HCR_EL2_TWI != 0 {
        let _ = writeln!(
            uart,
            "baleen: wfi OK: HCR_EL2.TWI is in force (HCR_EL2 read back as 0x{hcr:x}) — a guest \
             that goes idle YIELDS the pCPU instead of holding it with no way for EL2 to take it \
             back"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: wfi FAIL: HCR_EL2 read back as 0x{hcr:x} with TWI clear — an idle guest holds \
             the pCPU and the machine freezes the first time one is switched in while idle"
        );
        crate::park();
    }
    for slot in 0..NUM_GUESTS {
        let _ = writeln!(
            uart,
            "baleen: wfi: dom {} — {} WFIs trapped, {} of them yielded the pCPU to a peer (a count \
             of zero is a boot in which that guest never went idle, not a fault)",
            slot_dom(slot),
            WFI_TRAPS[slot].load(Ordering::Relaxed),
            WFI_YIELDS[slot].load(Ordering::Relaxed)
        );
    }
}

/// **The witness for EL2's own clock** (③-b2b-ii-e) — ledger item 9's structural closure.
///
/// ## What each conjunct is for, and why none of them is a count of what the guests did
///
/// * **`CNTHP_CTL_EL2` read back** with `ENABLE` set and `IMASK` clear. The register's own account
///   of whether EL2's timer is armed and audible, in the shape [`report_wfi_yield`] established. It
///   is stored on every arm, not only the cold start, so it describes the steady state.
/// * **PPI 26 enabled at the redistributor**, read back from `GICR_ISENABLER0`. Armed and
///   deliverable are two different facts: a timer counting into a masked PPI is a timer EL2 never
///   hears, and the whole rung is about EL2 not being lockable-out.
/// * **`expiries == deactivated`.** EL2 runs `EOImode=1`, so failing to issue `ICC_DIR_EL1` leaves
///   EL2's own interrupt Active and the GIC never signals it again — EL2 would get exactly one slice
///   for the entire boot, with every other marker still green. Read back from `GICR_ISACTIVER0`, the
///   controller's view rather than EL2's bookkeeping, which is the distinction ③-b2b-ii-c1 drew.
/// * **`expiries >= elapsed / (2 * quantum)`.** The floor, and the only conjunct that is a count —
///   deliberately, because it is a count of a quantity **the mechanism determines**: the deadline is
///   EL2's own, so how many times it expires follows from elapsed time divided by the quantum and
///   from nothing any guest contributes. It reads zero on a build without this rung. The factor of
///   two is the declared allowance for EL2's own service time between expiry and re-arm — real
///   handler latency is microseconds against a 10 ms slice, so the margin is ~1000×, and it is a
///   slack on EL2's behaviour rather than on a guest's.
///
/// ## What is reported and NOT asserted, and why that restraint matters here
///
/// The longest interval any guest held the pCPU is the number this rung is *about*, and it is still
/// only reported. A bound on it is not a valid gate: a cooperative guest keeps that interval far
/// below any quantum with EL2's clock switched off entirely, so the assertion would pass unchanged
/// on the build this rung replaces (design-lesson #105). Under the non-cooperation probe it is the
/// number to read; as a gate it would be theatre.
///
/// ## Honest ceiling, and the probes that stand where this witness cannot
///
/// This says EL2's clock is armed, audible, completed, and firing at the rate its own deadline
/// implies. It does **not** say EL2 regains control from a guest that refuses to cooperate — no
/// counter can, on a boot where both guests do cooperate. That claim is the probes', run as a 2×2
/// with a deterministic control rather than argued:
///
/// | | EL2 clock armed | disarmed |
/// |---|---|---|
/// | guests cooperate | interleaved: dom 2's first line arrives while dom 1 still has 350 to go | **no time-slicing at all** — dom 1 runs to completion, *then* dom 2 starts; this witness reads `slice FAIL` |
/// | **dom 1 cannot cooperate** | **dom 2 boots to userspace, reads its own `/proc/iomem`, powers off** — 159 of its lines interleaved before dom 1's last | **dom 2 never executes an instruction. Zero lines. The machine is dead.** |
///
/// "Cannot cooperate" is forced, not waited for: `HCR_EL2.TWI` off *and* dom 1's tick forwarding cut
/// at its 60th tick with PPI 27 disabled at the redistributor, so from a fifth of the way into its
/// boot dom 1 has no tick to take, no `wfi` that traps, and no other route by which the pCPU can
/// leave it. That is the ③-b2b-ii-c2 hang condition **forced** rather than reproduced at 2 runs in
/// 15 — which is what makes the bottom-right cell a control worth having.
///
/// Read the bottom row together. The same non-cooperating guest kills the machine outright without
/// EL2's clock and cannot even slow its peer down with it, and nothing differs between those two
/// runs except whether `CNTHP_CTL_EL2` was written with `ENABLE`.
///
/// The top-right cell is worth one more line, because it corrects something. `HCR_EL2.TWI` does not
/// cover for a missing EL2 clock the way it might appear to: with the clock disarmed the two kernels
/// ran strictly **sequentially** — one handover in the whole boot, at `SYSTEM_OFF`. A guest that
/// always has work never executes `wfi`, so the yield never fires, and before this rung the
/// every-eighth-guest-tick preemption was the *only* thing producing concurrency at all.
fn report_el2_slice(uart: &mut Pl011) {
    let ctl = CNTHP_CTL_READBACK.load(Ordering::Relaxed);
    let quantum = SLICE_QUANTUM.load(Ordering::Relaxed);
    let expiries = SLICE_EXPIRIES.load(Ordering::Relaxed);
    let deactivated = SLICE_DEACTIVATED.load(Ordering::Relaxed);
    let enabled = gic::ppi_is_enabled(gic::HYP_TIMER_INTID);
    let freq = crate::time::frequency();
    let elapsed = {
        use hv_hal::TimeSource;
        crate::time::GenericTimer
            .now()
            .saturating_sub(SLICE_FIRST_ARM.load(Ordering::Relaxed))
    };
    // The floor. `quantum == 0` means `arm_slice` was never called at all, which must fail rather
    // than divide by zero into a vacuous pass.
    let floor = if quantum == 0 {
        u64::MAX
    } else {
        elapsed / (2 * quantum)
    };
    let armed = ctl & CNTHP_CTL_EL2_ENABLE != 0 && ctl & CNTHP_CTL_EL2_IMASK == 0;
    let ok = armed && enabled && expiries == deactivated && expiries >= floor;

    let ms = |ticks: u64| ticks * 1000 / freq.max(1);
    if ok {
        let _ = writeln!(
            uart,
            "baleen: slice OK: EL2 re-enters the machine on ITS OWN clock — CNTHP_CTL_EL2 read back \
             as 0x{ctl:x} (ENABLE, IMASK clear), PPI {} enabled at the redistributor, {expiries} \
             slice expiries taken and {deactivated} controller-confirmed Active -> Inactive, over \
             {} ms at a {} ms quantum (floor {floor}). A guest that never idles and never takes its \
             tick can no longer hold the pCPU",
            gic::HYP_TIMER_INTID,
            ms(elapsed),
            ms(quantum)
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: slice FAIL: CNTHP_CTL_EL2 read back as 0x{ctl:x}, PPI {} enabled={enabled}, \
             {expiries} expiries against {deactivated} controller-confirmed deactivations and a \
             floor of {floor} over {} ms — EL2's clock is not armed, not audible, not being \
             completed, or not firing. Re-entry to EL2 is behavioural again and a guest can hold \
             the pCPU with no way to take it back",
            gic::HYP_TIMER_INTID,
            ms(elapsed)
        );
        crate::park();
    }
    for (slot, hold) in MAX_HOLD.iter().enumerate() {
        let held = hold.load(Ordering::Relaxed);
        let _ = writeln!(
            uart,
            "baleen: slice: dom {} — the longest it held the pCPU between two entries to EL2 was {} \
             ticks ({} us), against a quantum of {quantum} ticks ({} ms). Reported, not asserted, \
             and it exceeds the quantum for two reasons that are not this mechanism: the interval \
             is measured entry-to-entry so it carries EL2's own service time for the previous trap, \
             and QEMU runs the generic timer off the host clock, so host scheduling of the QEMU \
             thread appears here directly",
            slot_dom(slot),
            held,
            held * 1_000_000 / freq.max(1),
            ms(quantum)
        );
    }
}

/// **The witness for FP/SIMD isolation** (③-b2b-ii-f) — residue 4's closure.
///
/// ## The assertion is the read-back, and the interesting number is the one NOT asserted
///
/// `verified == switches` is structural: every restore must leave the hardware equal to the context
/// it restored from, on every switch, whatever the guests do. That is the quantity the mechanism
/// determines (#127), and it catches the failure this rung can actually have — a **partial**
/// restore, which on a boot that never touches the high registers is indistinguishable from a
/// correct one.
///
/// `FP_FOREIGN` is reported beside it and deliberately never asserted. It counts switch-ins where
/// the live register file belonged to the peer — i.e. the leak that would have happened — and it is
/// a claim about the WORKLOAD: two guests that never use floating point leave it at zero on a
/// perfectly good boot. Asserting it would be the fifth-plus repeat of this arc's standing mistake.
///
/// ## Honest ceiling
///
/// This says the register file the incoming guest resumes on is its own. It does **not** say a guest
/// *observed* the peer's data before the fix — that claim is the `CPTR_EL2.TFP` measurement recorded
/// in [`crate::fp`], which found ~31 first-FP-uses-after-a-switch per boot with the guest's own
/// `CPACR_EL1` permitting each one — nor is it a theorem: `hv-metal` is not a Kani target.
fn report_fp_isolation(uart: &mut Pl011) {
    for slot in 0..NUM_GUESTS {
        let dom = slot_dom(slot);
        let verified = FP_RESTORE_VERIFIED[slot].load(Ordering::Relaxed);
        let switches = SWITCHES[slot].load(Ordering::Relaxed);
        let foreign = FP_FOREIGN[slot].load(Ordering::Relaxed);
        if verified == switches {
            let _ = writeln!(
                uart,
                "baleen: fp OK: dom {dom} resumed on its OWN FP register file every time — {verified} \
                 of {switches} switch-ins read back v0..v31 + FPCR + FPSR equal to the context \
                 restored, and on {foreign} of them the file had been left holding the PEER's data \
                 (that count is the workload's, not the mechanism's)"
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: fp FAIL: dom {dom} verified {verified} FP restores across {switches} \
                 switch-ins — the register file EL2 restored is not the one the hardware holds, so \
                 part of v0..v31/FPCR/FPSR is being dropped and a guest resumes on its peer's \
                 floating-point state"
            );
            crate::park();
        }
    }
}

/// The per-guest counters, named by the mechanism that writes each one. One array, so the count in
/// the report below is derived and a counter cannot be added without appearing there.
const PER_GUEST_COUNTERS: [&str; 11] = [
    "GIC register traps",
    "INTID enables",
    "PL011 register traps",
    "console bytes",
    "console lines",
    "forwarded timer ticks",
    "mediated SGIs",
    "scheduler switches",
    // ⚠ ③-b2b-ii-e REPLACED two entries here, and the replacement is the point rather than a tidy-up.
    // They were "released hardware mappings" and "controller-confirmed deactivations", and both were
    // legitimate per-guest discriminators while a preemption was reached from the guest's own tick:
    // exactly one hardware-mapped list register was in flight at every switch, so each read ~65 per
    // guest and a zero meant a broken handoff. A slice expiry lands at an arbitrary instruction, so
    // the antecedent — the guest still holding an UNTAKEN forwarded tick — became a coincidence:
    // **MEASURED at 1 per guest on the first boot of this rung, down from 65.** That is a ~1.5%
    // window (Linux's GIC handler against a ~1.25 ms tick period), which means the next boot could
    // as easily produce zero and redden a gate with nothing wrong.
    //
    // Precisely the shape this arc keeps hitting: a counter that was pinned to the mechanism became
    // pinned to the workload the moment the mechanism changed underneath it. The equality that
    // matters (`released == deactivated`) is CONDITIONAL and is still asserted in
    // `report_timer_handoff`; what belongs *here* is a quantity every running guest produces.
    //
    // Both replacements are determined by EL2's clock and by nothing a guest chooses: a guest that
    // runs for longer than one quantum is handed over, and a guest that enters EL2 twice has a
    // measurable hold.
    "handovers",
    "longest pCPU hold",
    "refused peer accesses",
];

/// **③-b2b-ii-a's witness, inverted by ③-b2b-ii-c2: the per-guest state is INDEXED, not SHARED.**
///
/// **The claim had to change when the second guest started running, and the change is the rung.**
/// While only dom 1 ran, the falsifiable statement was about the PEER: dom 2 had never been
/// dispatched, so every one of its counters had to read zero, and a shared model or a stale index
/// would contaminate them with the runner's traffic. That statement is now meaningless — dom 2 makes
/// its own traffic.
///
/// What replaces it is stronger. With both guests running, **every guest's counters must be
/// non-zero**, and a shared model gives itself away the other way round: one guest's tallies would
/// carry both guests' work while the other's stayed at zero. There is no arrangement of shared state
/// that produces two independently non-zero sets. So the same check, read in the opposite direction,
/// witnesses the same property against a machine that can now actually violate it.
///
/// **Honest limit.** Non-zero on both sides proves the state is *two-valued*, not that each value
/// belongs to the right guest. What binds a counter to its owner is elsewhere and stronger: dom 2's
/// console lines carry `baleen-guest-ram: 64000000-7fffffff`, which is dom 2's kernel reading dom
/// 2's DTB through dom 2's Stage-2, and which dom 1 cannot produce.
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
            HANDOVERS[slot].load(Ordering::Relaxed),
            MAX_HOLD[slot].load(Ordering::Relaxed),
            PEER_FAULTS[slot].load(Ordering::Relaxed),
        ]
    };

    // The first counter any guest failed to move, if any — named, because "this guest never ran" and
    // "this guest's GIC model is the other one's" are different bugs and the counter says which.
    let mut dead = None;
    for slot in 0..NUM_GUESTS {
        // ⚠ **A domain RETIRED FOR A FAULT is skipped, and this is not a loosened check.** These
        // counters assert that each guest exercised each mechanism; a guest stopped part-way through
        // its own boot legitimately never reached some of them, so its zeros record HOW FAR IT GOT
        // rather than a defect. Asserting them anyway is design-lesson #127 — a claim about the
        // workload wearing the clothes of an invariant — and it is exactly what the fault probe
        // caught: dom 1, retired during its AMBA bus scan, had never raised an SGI, and this loop
        // parked the boot over a zero that was correct.
        //
        // The shipped configuration is UNAFFECTED: both guests power off cleanly, neither is
        // skipped, and every counter is asserted exactly as before.
        if retirement_of(slot) == Retirement::Faulted {
            let _ = writeln!(
                uart,
                "baleen: perguest: dom {} was RETIRED FOR A FAULT — its counters are not asserted, \
                 because a guest stopped part-way through its boot has correct zeros",
                slot_dom(slot)
            );
            continue;
        }
        for (name, value) in PER_GUEST_COUNTERS.iter().zip(sample(slot)) {
            if value == 0 && dead.is_none() {
                dead = Some((slot_dom(slot), *name));
            }
        }
    }

    match dead {
        None => {
            let _ = writeln!(
                uart,
                "baleen: perguest OK: the guests' device models, vCPU contexts and witnesses are \
                 INDEXED, not shared — all {} of them are non-zero for EVERY one of the \
                 {NUM_GUESTS} guests, which no arrangement of shared state produces (a shared \
                 model carries both guests' work in one tally and leaves the other at zero)",
                PER_GUEST_COUNTERS.len()
            );
            for slot in 0..NUM_GUESTS {
                let c = sample(slot);
                let _ = writeln!(
                    uart,
                    "baleen: perguest: dom {} — {} GIC traps, {} INTID enables, {} PL011 traps, {} \
                     console bytes on {} lines, {} forwarded ticks, {} SGIs, {} dispatches, {} \
                     handovers, longest hold {} ticks, {} refused peer accesses",
                    slot_dom(slot),
                    c[0],
                    c[1],
                    c[2],
                    c[3],
                    c[4],
                    c[5],
                    c[6],
                    c[7],
                    c[8],
                    c[9],
                    c[10]
                );
            }
        }
        Some((dom, name)) => {
            let _ = writeln!(
                uart,
                "baleen: perguest FAIL: dom {dom}'s '{name}' counter is ZERO — that guest never \
                 exercised the mechanism, or its state is shared with a peer that did"
            );
            crate::park();
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
        "baleen: M5 Arc 5e — booting {NUM_GUESTS} REAL aarch64 Linux kernels as EL1 guests \
         time-slicing ONE pCPU (dom {GUEST_A} owns 0x{GUEST_RAM_BASE:08x}..0x{split:08x}, dom \
         {GUEST_B} owns 0x{split:08x}..0x{GUEST_RAM_END:08x})",
        split = stage2::LINUX_RAM_SPLIT
    );

    // ③-b2b-ii-b — BEFORE anything else, read what the loader actually deposited. Every guest's
    // payload, not only the peer's: guest A's is known-good, so A passing while B fails says the
    // check is right and the load is wrong.
    report_loaded_images(uart);

    // Build the guest's model and emit its Stage-2 through the PROVEN emitter (M5 Arc 6b).
    *crate::guest::GUEST_HV.borrow_mut() = Some(crate::build_hypervisor());
    let mut cell = crate::guest::GUEST_HV.borrow_mut();
    let hv = match cell.as_mut() {
        Some(hv) => hv,
        None => crate::park(),
    };
    // ③-b2a — TWO domains, TWO Stage-2 images; since ③-b2b-ii-c2, TWO running kernels.
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
    // Keep each domain's VMID-tagged image where a switch can install it (③-b2b-ii-c2). Stored only
    // after `report_disjointness` has walked both to their descriptors — an image nothing has read
    // back is not one to start dispatching guests onto.
    for (slot, v) in vttbr.iter().enumerate() {
        VTTBR[slot].store(*v, Ordering::Relaxed);
    }

    // ③-b2b-i put guest A's vCPU under hv-core's REAL scheduler before it ever ran, so the
    // preemption at each timer tick is a pair of transitions against a model that already has it
    // Running rather than a pair of calls the model would refuse. **③-b2b-ii-c2 admits EVERY
    // guest's**, and that is what makes a switch to the peer legal: `next_runnable` picks only
    // vCPUs the model reports `Runnable`, so a vCPU nobody ever admitted is one the scheduler would
    // never hand the CPU to.
    //
    // Admit moves each Offline → Runnable; the single dispatch moves guest A's Runnable → Running.
    // Guest B stays Runnable until the first timer tick preempts A — its first instruction is
    // executed by a context RESTORE, not by an `eret` of its own (see `VcpuCtx::seed_boot`).
    let now = {
        use hv_hal::TimeSource;
        crate::time::GenericTimer.now()
    };
    for slot in 0..NUM_GUESTS {
        sched_on(
            hv,
            slot_dom(slot),
            HvCall::SchedAdmit { vcpu: LINUX_VCPU },
            "admit a linux vcpu",
        );
    }
    sched_on(
        hv,
        GUEST_A,
        scheduler_run(now),
        "dispatch the first linux vcpu",
    );
    let _ = writeln!(
        uart,
        "baleen: {NUM_GUESTS} linux vcpus admitted through hv-core's scheduler, dom {GUEST_A} \
         dispatched onto pCPU {PCPU0} — each guest runs for at most one {EL2_SLICE_HZ} Hz EL2 \
         slice, and the pCPU passes to whichever peer the model still reports Runnable"
    ); // Name the saved set in the transcript. A context register that stops being saved is otherwise
       // invisible until it corrupts a guest; here it changes this line, so the boot output itself
       // records what this build believes a vCPU is made of.
    let _ = write!(
        uart,
        "baleen: vcpu context = {} components (",
        vcpu::CTX_COMPONENTS.len()
    );
    for (i, c) in vcpu::CTX_COMPONENTS.iter().enumerate() {
        let _ = write!(uart, "{}{c}", if i == 0 { "" } else { " " });
    }
    let _ = write!(uart, ") / {} registers:", vcpu::CtxReg::ALL.len());
    for r in vcpu::CtxReg::ALL {
        let _ = write!(uart, " {}", r.name());
    }
    let _ = writeln!(uart);

    drop(cell);
    enable_stage2(vttbr[SLOT_A]);
    enable_guest_hw_access();
    init_guest_el1();

    // ③-b2b-ii-c2 — **seed every guest that is not the one this `eret` enters.**
    //
    // Guest A is entered the way it always was: `ELR_EL2`/`SPSR_EL2` written below, then `eret`.
    // Guest B is never entered that way at all — its first instruction is executed by the context
    // RESTORE inside `switch_context`, exactly like its ten-thousandth. So there is no second entry
    // sequence to keep in step with the first, and no boot path that runs once and is then never
    // exercised again.
    //
    // `SCTLR_EL1` is read back from the live CPU rather than recomputed: `init_guest_el1` just
    // cleared the enables on it, so this is the identical value guest A is about to be entered with,
    // RES1 bits included. Two answers to "what `SCTLR_EL1` does a guest boot with" would agree
    // until a board changed.
    let sctlr_at_boot: u64;
    // SAFETY: `SCTLR_EL1` is readable at EL2; no memory effect.
    unsafe {
        asm!("mrs {v}, sctlr_el1", v = out(reg) sctlr_at_boot, options(nomem, nostack, preserves_flags));
    }
    {
        let mut ctx = VCPU_CTX.borrow_mut();
        for slot in (0..NUM_GUESTS).filter(|&s| s != SLOT_A) {
            ctx[slot].seed_boot(
                kernel_entry(slot),
                dtb_addr(slot),
                SPSR_EL2_LINUX,
                sctlr_at_boot,
            );
            let _ = writeln!(
                uart,
                "baleen: dom {} seeded for its first switch-in — entry 0x{:08x}, x0 = DTB \
                 0x{:08x}, SPSR 0x{SPSR_EL2_LINUX:x}, SCTLR_EL1 0x{sctlr_at_boot:x} (MMU off, as \
                 the arm64 boot protocol requires); it is entered by a context restore, not an eret",
                slot_dom(slot),
                kernel_entry(slot),
                dtb_addr(slot)
            );
        }
    }

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
    // ③-b2b-ii-e — EL2's OWN timer PPI, separate from the call above because that one is shared with
    // the synthetic path and the synthetic path has no EL2 clock.
    gic::enable_hyp_timer_ppi();
    gic::enable_physical_cpu_interface_el2();
    gic::set_eoi_mode_split();
    gic::enable_el2();
    // An idle guest should yield rather than burn its slice. Since ③-b2b-ii-e this is efficiency,
    // not liveness — see `report_wfi_yield`.
    HCR_WITH_TWI.store(trap_guest_wfi(), Ordering::Relaxed);

    let _ = writeln!(
        uart,
        "baleen: EL2 takes the guest's interrupts — HCR_EL2.IMO=1, timer PPI {} forwarded by \
         hardware-mapped list-register injection",
        gic::VTIMER_INTID
    );

    // ③-b2b-ii-e — **start EL2's clock, with the same call every switch makes.** The last thing
    // before the `eret`, so no guest ever runs un-deadlined; and `arm_slice` rather than a bespoke
    // cold-start sequence, so there is no arming code that runs once and is never exercised again
    // (design-lesson #130, the same reasoning that seeds guest B rather than `eret`-ing into it).
    let ctl = arm_slice();
    let _ = writeln!(
        uart,
        "baleen: EL2 arms a clock of its OWN — CNTHP_EL2 at {} Hz on PPI {} (CNTHP_CTL_EL2 read \
         back as 0x{ctl:x}), so the pCPU comes back to EL2 whether or not the guest cooperates",
        EL2_SLICE_HZ,
        gic::HYP_TIMER_INTID
    );

    let _ = writeln!(uart, "baleen: entering EL1 — the kernel takes the machine");

    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    // SAFETY: transfers to EL1 via `eret`; `DTB_ADDR` is the loaded DTB, `exc_stack_top` the EL2
    // trap stack. Never returns.
    unsafe { __enter_linux(DTB_ADDR, exc_stack_top) }
}
