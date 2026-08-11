// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # M5 Arc 5e — the real-Linux capstone (feature `real-linux`)
//!
//! The documented drop-in from `docs/ARC-5-M5-GUEST-INTERFACE.md`: boot a **real** aarch64 Linux
//! kernel as an EL1 guest, on the interfaces the synthetic Arc 0–5 guests already proved sound.
//! **No isolation content** — the thesis (Arcs 0–4) is proven on the un-forgeable synthetic guests;
//! this arc only demonstrates the already-proven hardware interface carries an unmodified kernel.
//! `hv-core`/`hv-hal` are untouched; this whole module is behind the `real-linux` feature, so the
//! default build (the CI boot-test) is byte-for-byte unchanged.
//!
//! ⚠ **"No isolation content" STOPPED BEING TRUE AT ⑲-2, and is now decisively false.** This file
//! carries the device half of the isolation claim: `report_dma_inflight` (feature `smmu`, so it is
//! not linkable from every configuration's docs) observes a bus master
//! confined by a real guest's own DERIVED Stage-2 binding while both kernels execute, and
//! [`report_dma_pad`] is what makes a landing site available to aim it at. The sentence above is
//! kept because it is true of the arc's ORIGINAL scope and explains why the file is shaped the way
//! it is — but read it as history, not as a description of what is asserted here today.
//!
//! ★★ **⑱-7 added a THIRD axis, and this file is the only place it exists.** Interrupt confinement
//! between guests, and **nothing under the `hv-vdev` proof fence can help**: `vcpu_affinity` takes
//! no guest argument, so two guests' vCPUs have identical affinities and no decode can tell them
//! apart. ⑱-7 found it resting on one `g != slot` guard repeated at four call sites; **⑱-8 replaced
//! that with a role** — [`crate::role::Running::own_vcpus`] yields only this guest's vCPUs, so the
//! comparison is gone rather than merely correct. See `docs/INTERRUPT-CONFINEMENT.md`.
//! [`AFFINITY_COLLISIONS`] measures the HAZARD the role removes, not a guard firing.
//!
//! ⚠ **THIS PARAGRAPH SAID "a SINGLE EL1 guest that owns the machine" UNTIL ⑱-4b, AND HAD BEEN
//! FALSE SINCE ③-b2b-ii.** What actually boots today is **two** unmodified kernels, each with
//! **two vCPUs** (⑱-4b-ii's `PSCI CPU_ON`), time-slicing one physical CPU — four vCPUs in total,
//! each guest reporting `SMP: Total of 2 processors activated.` and owning half the RAM window
//! behind its own proven-emitted Stage-2 image. "Owns the machine" is the one phrase of the original
//! framing that has to go: a guest owns its RAM and nothing else, and now not even a CPU to itself.
//!
//! ⚠ **AND THAT COUNT IS NOW PER-CONFIGURATION, so do not read "two kernels" as a property of this
//! file.** Under `--features monitor` one slot carries a small bare-metal partition
//! (`Payload::Monitor`, from `crate::monitor`) instead of a kernel — the mixed-criticality role
//! `docs/CONSUMER-CORTENFORGE.md` derives. Neither name is an intra-doc link because both exist
//! only under that feature, where a link would break every other config's rustdoc.
//! **Read [`payload_of`] for what a slot carries and
//! [`runs_linux`] before asserting anything about a kernel.** The paragraph above is left as it
//! stands because it is true of the shipped `real-linux` boot; this pointer is here because the
//! ⑱-4b correction it records was itself missed in three other files for want of exactly such a
//! pointer, which is the lesson #195 paid for.
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
//! **The tree has now gained THREE nodes, and the distinction is worth keeping sharp.** The property
//! earned above is that *taking a device away from a guest never required editing its description*;
//! that is untouched, because no addition takes anything away.
//!
//! * **③-b2b-ii-d — the peer probe.** Not an accommodation of our emulation: it is the negative
//!   test's instrument, the one node in the tree that exists in order to FAIL.
//! * **⑱-4b-ii — `cpu@1`.** The other direction of the same property, and the honest exception to
//!   it: a guest cannot USE a CPU its machine description does not mention, so GIVING it one has to
//!   be said in the tree. Taking away needs no edit; handing over does.
//! * **⑲-3a — `reserved-memory/dma-pad`.** The top 2 MiB of each window, `no-map`, so that a bus
//!   master has somewhere to land that the kernel is DECLARED not to touch rather than observed not
//!   to. See [`dma_pad_ipa`] and [`report_dma_pad`]. This one is closest to an accommodation and
//!   should be called that: the guest gives up 2 MiB of usable RAM to make a hypervisor-side
//!   experiment safe, and it pays that cost in every configuration, not only the one that DMAs.
//!
//! Say "the DTS gained a probe, then a second CPU, then a reserved range" — not "the DTS is
//! untouched".
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
//! `crate::park()` still exists here, and now means **EL2 itself is in a state it cannot describe**
//! (the model refused a transition, a `BootCell` was already borrowed). The diagnostics for guest
//! faults are prefixed `guest FAULT:` rather than `LINUX GUEST TRAP:` so that the latter keeps that
//! narrower meaning — and stays forbidden by the boot gate in *both* of its runs.
//!
//! **All NINE guest-reachable halts this path had are now closed** — seven by [`fault_retire`], the
//! forwarded timer by deferral, and [`handle_peer_fault`]'s loop cap by retirement. Every remaining
//! `park()` here is EL2 declaring its own state indescribable.
//!
//! ⚠ **Say "all nine KNOWN", and keep saying it.** The sweep that drove this work reported EIGHT and
//! there were nine: the ninth appeared in its own park-to-function mapping and was dropped when the
//! summary table was written. An audit that undercounted once is not evidence of completeness the
//! second time. **The claim this file can support is "every `park()` reachable from
//! [`handle_linux_sync`] or [`handle_linux_irq`] has been enumerated and closed" — which is a
//! statement about a procedure that has already failed once, not a theorem.** `hv-metal` is not a
//! Kani target; nothing here proves the enumeration is complete.
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
//! The emulated UART is still transmit-only, but ⑱-6 changed *why*. This used to end "its RX path
//! needs a forwarded SPI, which ③-a2's machinery supports but nothing yet wires" — and the wiring
//! now exists: [`deliver_spi`] routes an SPI to the vCPU the guest aimed it at, and the INTID its
//! witness uses is **the UART's own** (33, from `guest.dts`). What is missing is no longer a
//! delivery path but a **source**: [`crate::vpl011`] never asserts an interrupt, because nothing
//! feeds it input. An RX path would supply that and use `deliver_spi` unchanged.
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
use hv_vdev::gicv3::vcpu_affinity;

use crate::abort::{self, DataAbort, EC_DATA_ABORT};
use crate::cell::BootCell;
use crate::console::GuestConsole;
use crate::ctx::CtxComponent;
use crate::gic;
use crate::pl011::Pl011;
use crate::role::{Incoming, Outgoing, PerGuest, PerVcpu, Running, VcpuIdx, VCPUS_PER_GUEST};
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

/// **What a guest slot actually carries.**
///
/// Until the `monitor` configuration every slot ran an unmodified Linux kernel, so "which guest" was
/// the only per-slot axis and "is it Linux" was not a question anything could ask. It is now, and
/// this is the one place that answers it.
///
/// ★ **A value rather than a `#[cfg]` at each use site, and that is the rung's main structural
/// decision.** Roughly a dozen per-guest reports assert Linux-workload facts — a userspace marker in
/// the transmit stream, a kernel's bus scan, a device tree's reservations. Under a `#[cfg]` per site
/// each of those is an independent chance to forget one, and a forgotten one does not fail: it
/// **asserts a Linux fact about a partition that never ran Linux**, and the zero it reads is
/// correct. That is design-lesson #127's shape exactly, and [`witnesses_assertable`] exists because
/// the fault probe already found three reports doing it.
///
/// ⚠ **A skipped assertion must SAY it was skipped.** A report that quietly drops a slot presents a
/// subset as a total — the defect ⑳-f was built to catch, written into the guard against it. Every
/// site that consults this prints which slots it covered and why.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Payload {
    /// An unmodified aarch64 Linux kernel, loaded by QEMU `-device loader`.
    Linux,
    /// [`crate::monitor`]'s bare-metal payload, copied out of hv-metal's own `.rodata`.
    #[cfg(feature = "monitor")]
    Monitor,
}

/// The slot carrying the bare-metal monitor in the `monitor` configuration.
///
/// **Not slot A**, and the constraint is structural rather than a preference: slot A is the one
/// entered by `run`'s `eret`, with `ELR_EL2`/`SPSR_EL2` written directly, while every other slot is
/// entered by a context restore from [`crate::vcpu::VcpuCtx::seed_boot`]. Putting the monitor on a
/// restored slot is what makes it a *payload swap* instead of a second entry sequence.
#[cfg(feature = "monitor")]
pub(crate) const MONITOR_SLOT: usize = SLOT_B;

#[cfg(feature = "monitor")]
const _: () = assert!(
    MONITOR_SLOT != SLOT_A,
    "the monitor must sit on a context-restored slot; slot A is entered by run()'s own eret"
);

// ─── ㉗: the one-way observation channel ─────────────────────────────────────────────────────────
//
// ⚠⚠ **THIS IS THE ONE PLACE THE TWO PARTITIONS ARE NOT DISJOINT, AND IT IS DELIBERATE.** ㉖
// established co-residency with `no channel`; ㉗ gives the monitor a READ-ONLY view of one frame of
// the policy partition's RAM, because a monitor that observes nothing is not a monitor.
//
// ★ **The authorization is the model's, not this file's.** `hv_core`'s `p2m_link` refuses a foreign
// child unless `grant.authorizes(owner, caller, child, writable)` — "any grant for a read-only one"
// — and `hv-verify`'s `an_unauthorized_frame_is_never_mapped` is stated over exactly that relation
// ("a frame a domain neither owns nor holds a grant for is not in the table at all"). So the
// monitor's descriptor is emitted BY THE PROVEN EMITTER from an authorized edge; nothing here writes
// a descriptor, and nothing here is a special case in the emitter.
//
// ## ★★ THE KILL PROBES — all four run, all four killed (2026-08-11)
//
// A channel witness that cannot fail is decorative, which is the lesson ㉕ paid four probes to
// learn. Each of these was applied to a working tree, booted, and reverted.
//
// | # | probe | result |
// |---|---|---|
// | 1 | ask for a **writable** link while holding only the read-only grant | `Unauthorized` — the model refuses; **the monitor cannot widen its own view** |
// | 2 | delete the grant entirely, keep the link | `Unauthorized` — the leaf exists *because* of the grant, not because it was written |
// | 3 | read-write grant + writable link, **descriptor check left asserting** | `observe FAIL … got Reach { perm: Rw, xn: false }` — **voice 1** catches it |
// | 4 | the same, with the descriptor check **relaxed** so the payload runs | the payload's own readback prints `OBSERVE FAIL … my store LANDED` — **voice 3** catches it |
//
// ★ Probe 4 is the one that matters, because it is the only one that tests the witness the monitor
// makes **for itself**: same three instructions, on a leaf that really is writable, opposite verdict.
// ⚠ And note how 3 and 4 compose: with a writable leaf there is no fault, so `observe OK` (voice 2)
// is correctly **absent** while voice 3 FAILs. The two disagree in the same direction, which is what
// independent witnesses are supposed to do — had voice 2 still fired, it would have been reporting a
// refusal that never happened.

/// The model frame the monitor observes: **guest A's first**, whose window base is where its kernel
/// `Image` was loaded.
///
/// ★ Chosen so the observation has a **checkable** value rather than merely a readable one: this
/// frame carries `IMAGE_MAGIC` at [`IMAGE_MAGIC_OFF`], which [`report_loaded_images`] independently
/// verifies from EL2 before any guest runs. The monitor comparing against it is therefore a claim
/// two separate readers agree on, not "the load returned something".
#[cfg(feature = "monitor")]
const OBSERVED_FRAME: Mfn = first_frame(SLOT_A);

/// The IPA the monitor reaches [`OBSERVED_FRAME`] at.
///
/// ⚠⚠ **NOT A CHOICE — it is the address its OWNER sees it at, and that is what forces this rung to
/// weaken [`report_disjointness`].** `hv_s2::leaf_map_from_edges` indexes its output by the CHILD
/// FRAME, and the emitter maps `IPA(m) -> PA(m)`; so a granted frame necessarily appears in the
/// grantee's image at the grantor's address, inside the grantor's half of the RAM window. Mapping it
/// anywhere else would mean changing the refinement relation itself, which is Architecture Audit
/// #2's subject and is proven in `hv-verify`. **There is no version of this rung in which the two
/// images stay disjoint over the guest-RAM window.**
#[cfg(feature = "monitor")]
pub(crate) const OBSERVED_IPA: u64 = guest_ram_base(SLOT_A);

/// The offset, within the monitor's own window, of the frame it **gives up** to make room.
///
/// ⚠ **There is no free table slot.** `LINUX_TABLES_PER_GUEST` (28) × `TABLE_SLOTS` (8) = **224** =
/// `LINUX_SUP_FRAMES_PER_GUEST` exactly, so every slot a guest has is already populated by one of
/// its own frames. Rather than grow the partition — which would move `NUM_LINUX_TABLES`,
/// `NUM_FRAMES` and `PARTITION`'s shape, all checked against `hv-part` predicates proven
/// ∀-partition — **the monitor trades one of its own frames for the view**. Its payload is a few
/// hundred bytes in a 448 MiB window, so the 2 MiB hole costs it nothing real, and the trade is
/// visible in the counts rather than hidden.
///
/// ⚠ **The byte count is deliberately NOT written here.** It said "284-byte payload" and was wrong
/// within this very rung — ㉗'s additions took it to 532 — which is #276 in its purest form, in a
/// comment by the author who had just finished documenting #276. `monitor::load` prints the real
/// size, measured, on every boot; that is the only place it belongs.
///
/// ⚠⚠ **NOT the last frame, and this is load-bearing:** `DMA_PAD_SIZE` is exactly one super frame at
/// the TOP of each window, so the pad **is** offset `LINUX_SUP_FRAMES_PER_GUEST - 1` — and
/// [`seed_dma_pads`], [`report_dma_pad`] and ⑲-3b's in-flight witness all read it. Vacating that one
/// would break three consumers in a way the boot would not explain. This is the second-to-last,
/// which nothing else names.
#[cfg(feature = "monitor")]
const VACATED_OFFSET: u64 = stage2::LINUX_SUP_FRAMES_PER_GUEST - 2;

#[cfg(feature = "monitor")]
const _: () = assert!(
    VACATED_OFFSET * stage2::SUP_FRAME_BYTES
        != stage2::LINUX_SUP_FRAMES_PER_GUEST * stage2::SUP_FRAME_BYTES - DMA_PAD_SIZE,
    "the monitor would give up the frame its DMA landing pad lives in; seed_dma_pads, \
     report_dma_pad and the in-flight witness all read that frame"
);

/// The grant slot, in **guest A's** table, that carries the monitor's view.
#[cfg(feature = "monitor")]
const OBSERVE_GREF: hv_core::grant::GrantRef = 0;

/// What guest `slot` carries. Total over the slots this build deploys.
pub(crate) const fn payload_of(slot: usize) -> Payload {
    #[cfg(feature = "monitor")]
    if slot == MONITOR_SLOT {
        return Payload::Monitor;
    }
    let _ = slot;
    Payload::Linux
}

/// Whether `slot` runs a real kernel — the guard every Linux-workload witness consults.
pub(crate) const fn runs_linux(slot: usize) -> bool {
    matches!(payload_of(slot), Payload::Linux)
}

/// **Whether `slot`'s Linux-DRIVER witnesses apply — and if they do not, SAY SO on the wire.**
///
/// A whole family of per-guest witnesses assert that a kernel's driver traffic went through EL2's
/// emulation: forwarded timer ticks, GIC register traps, mediated SGIs, routed SPIs, affinity
/// collisions. Every one of them reads **zero** for a partition that has no drivers, and zero is the
/// *correct* reading — the same shape [`witnesses_assertable`] exists for, arriving through a
/// different door. (Measured: the first boot of the `monitor` configuration produced six such
/// FAILs, all of them true statements about a machine that was working.)
///
/// ⚠⚠ **The exemption is PRINTED, and that is the whole design of this function.** A guard that
/// merely `continue`d would leave the transcript looking exactly like a boot where those witnesses
/// had been asserted and passed — a subset presented as a total, which is the defect ⑳-f was built
/// to catch. So the skip is a line on the wire naming the slot, the mechanisms, and the reason.
///
/// ★ **The Linux partition's witnesses are NOT weakened by this.** Each of these reports loops over
/// slots and asserts per-slot; exempting a slot with no drivers removes nothing from the slot that
/// has them, which is why this is a per-slot question and not a per-boot one.
fn linux_driver_witnesses_apply(slot: usize, uart: &mut Pl011) -> bool {
    if runs_linux(slot) {
        return true;
    }
    let _ = writeln!(
        uart,
        "baleen: driverwitness n/a: dom {} carries the bare-metal monitor payload — it runs no \
         kernel and drives no GIC, timer, SGI or SPI, so the vtimer / vgic / vsgi / vspi / \
         irqconfine / perguest witnesses have nothing to observe for this slot and are NOT asserted \
         for it. They ARE asserted, unchanged, for every slot that runs Linux",
        slot_dom(slot)
    );
    false
}

/// What `slot` carries, and — for a Linux slot — the reason its landing pad stayed untouched.
///
/// The two halves of the pad claim are genuinely different evidence: a kernel honoured a `no-map`
/// reservation it read out of its own device tree (asserted independently by the `OF: reserved mem:
/// … nomap …` markers), while the bare-metal payload has no device tree and simply never addresses
/// the range. Collapsing both into "its device tree reserves no-map" is what made that line false
/// for a slot with no device tree.
fn payload_kind(slot: usize) -> &'static str {
    if runs_linux(slot) {
        "unmodified Linux, no-map reserved in its own device tree"
    } else {
        "bare-metal monitor, which has no device tree and never addresses the range"
    }
}

/// What `slot` carries, for a transcript line. Short enough to sit inside a sentence.
fn payload_name(slot: usize) -> &'static str {
    if runs_linux(slot) {
        "kernel 'ARM\\x64'"
    } else {
        "bare-metal payload"
    }
}

/// **Whether guest `slot`'s RAM window still holds the payload EL2 deposited in it**, and the word
/// that was actually read there.
///
/// The signature differs per payload — an `Image` carries its magic at [`IMAGE_MAGIC_OFF`], the
/// bare-metal payload is raw instructions from its first byte — so this reads the right place and
/// compares against the right thing. Returned as a pair so a failing caller can print what it saw
/// rather than only that it disagreed (design-lesson #71: a check whose diagnostic cannot
/// discriminate is half a check).
fn peer_payload_at(slot: usize) -> (bool, u32) {
    if runs_linux(slot) {
        let magic = peek::u32_at(guest_ram_base(slot) + IMAGE_MAGIC_OFF);
        return (magic == IMAGE_MAGIC, magic);
    }
    #[cfg(feature = "monitor")]
    {
        let word = peek::u32_at(guest_ram_base(slot));
        (word == crate::monitor::first_word(), word)
    }
    // Unreachable without the feature — `runs_linux` is total and returns `true` for every slot when
    // no payload swap is compiled in — but written as a value rather than an `unreachable!()`: this
    // runs inside a fault handler, where a panic would replace a real diagnostic with a worse one.
    #[cfg(not(feature = "monitor"))]
    (false, 0)
}

/// How many slots run an unmodified kernel, and how many carry a bare-metal payload.
///
/// Derived from [`payload_of`] rather than written down, so the boot banner and the per-payload
/// reports cannot claim a division of the machine that the seeding does not perform.
const fn count_payload(want_linux: bool) -> usize {
    let mut n = 0;
    let mut slot = 0;
    while slot < NUM_GUESTS {
        if runs_linux(slot) == want_linux {
            n += 1;
        }
        slot += 1;
    }
    n
}

/// Slots running an unmodified Linux kernel.
const NUM_LINUX: usize = count_payload(true);
/// Slots carrying a bare-metal payload.
const NUM_MONITOR: usize = count_payload(false);

const _: () = assert!(
    NUM_LINUX + NUM_MONITOR == NUM_GUESTS,
    "the payload census does not cover every slot"
);

/// **At least one slot still runs Linux.** The configuration is *mixed* criticality: a monitor with
/// no partition to sit beside would make every peer-relative witness in this file vacuous.
const _: () = {
    let mut any = false;
    let mut slot = 0;
    while slot < NUM_GUESTS {
        if runs_linux(slot) {
            any = true;
        }
        slot += 1;
    }
    assert!(
        any,
        "no slot runs Linux — the mixed-criticality claim needs a real kernel to be mixed WITH"
    );
};

/// A guest slot's model [`DomId`]. Dom 0 is the control domain, so guest slot `i` is dom `i + 1`.
///
/// One derivation for the whole file: the domain id, the Stage-2 set, the frame range and the table
/// range are all functions of the slot, so a third guest would be a change to [`NUM_GUESTS`] and
/// nothing else. (`pub(crate)` for [`crate::console`], which tags each guest's console lines and
/// must name the same domain this file dispatches to.)
pub(crate) const fn slot_dom(slot: usize) -> DomId {
    PARTITION.dom_of(slot as u64)
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
    PARTITION.first_frame(slot as u64) as Mfn
}

/// The first model frame holding an `L2` page table for guest `slot` — just above the super
/// partition, in the base partition, and never mapped (a page table is model state, not a leaf).
/// Each domain gets its own contiguous run of `LINUX_TABLES_PER_GUEST`.
const fn first_table(slot: usize) -> Mfn {
    PARTITION.first_table(slot as u64) as Mfn
}

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
///
/// ⑱-3a: this now holds a **(guest, vCPU) pair**, packed by [`Running::pack`]. The packing lives in
/// `crate::role` because a second encoding of "who is running" is the defect ⑭ spent a rung removing,
/// and because keeping it there is what stops this file rebuilding a role out of arithmetic.
static CURRENT: AtomicUsize = AtomicUsize::new(Running::at_boot(SLOT_A).pack());

/// The vCPU currently executing at EL1.
fn current_vcpu() -> Running {
    Running::unpack(CURRENT.load(Ordering::Relaxed))
}

/// The **guest** currently executing at EL1 — the projection the report and handler code wants,
/// where there is one subject and no role to confuse.
///
/// ⚠ **Kept as its own function precisely because the projection must be explicit.** With
/// `VCPUS_PER_GUEST == 1` the packing is the identity, so `CURRENT.load()` would still return the
/// right slot by arithmetic coincidence — and would silently stop doing so at ⑱-3b. That is the
/// shape of defect this whole arc is spent on; it is not worth reproducing in the one line that
/// would be cheapest to get wrong.
fn current_slot() -> usize {
    current_vcpu().guest()
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

/// **How this machine is divided among guest slots — the deployment, and the ONE instance.**
///
/// The arithmetic moved to `hv-part` (㉒): it used to be four `const fn`s here, guarded by
/// `const assert!`s evaluated at the two slots this board deploys, and `hv-metal` is
/// workspace-EXCLUDED so no proof could reach them. What stays here is which numbers go in.
///
/// ★ **The link that makes the proofs load-bearing rather than decorative is the `const assert!`
/// below**: the shipped partition is checked against the very predicates `hv-verify` proves total
/// for a symbolic partition. Without it this crate could deploy a partition the proofs say nothing
/// about, and the proofs would be true of a shape nothing uses.
pub(crate) const PARTITION: hv_part::Partition = hv_part::Partition {
    num_guests: NUM_GUESTS as u64,
    frames_per_guest: stage2::LINUX_SUP_FRAMES_PER_GUEST,
    window_len: hv_part::window_len_from(
        stage2::LINUX_SUP_FRAMES_PER_GUEST,
        stage2::SUP_FRAME_BYTES,
    ),
    ram_base: stage2::LINUX_RAM_BASE,
    ram_end: stage2::LINUX_RAM_END,
    num_sup_frames: stage2::NUM_SUP_FRAMES,
    tables_per_guest: stage2::LINUX_TABLES_PER_GUEST,
    vcpus_per_guest: VCPUS_PER_GUEST as u64,
};

/// The deployed partition satisfies the predicates proven ∀-partition in `hv-verify::partition`.
const _: () = {
    assert!(
        PARTITION.is_well_formed(),
        "the deployed partition is outside the shape hv-part's proofs are stated for"
    );
    assert!(
        PARTITION.windows_disjoint(),
        "two guest slots' RAM windows overlap"
    );
    assert!(
        PARTITION.windows_in_range(),
        "a guest slot's RAM window runs past the backed window"
    );
    assert!(
        PARTITION.frames_disjoint(),
        "two guest slots overlap in the model's frame index space"
    );
};

/// The base of guest `slot`'s RAM window — the address its `Image` loads at and the base its DTB's
/// `/memory` node advertises. Derived from which model frames the guest owns, so it cannot disagree
/// with what the emitter maps for it.
const fn guest_ram_base(slot: usize) -> u64 {
    PARTITION.window_base(slot as u64)
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

/// ⑲-3a — the size of each guest's **DMA landing pad**, the top slice of its own window that its
/// device tree reserves `no-map`.
///
/// One Stage-2 block, so the reservation can neither straddle two blocks nor force the emitter to
/// split one. Mirrored by `xtask`'s `LINUX_DMA_PAD_SIZE`, and the two are held together by
/// `render_guest_dtb`'s checked substitution of the `reg` this size appears in.
const DMA_PAD_SIZE: u64 = 0x20_0000;

/// The IPA of guest `slot`'s DMA landing pad — the top [`DMA_PAD_SIZE`] of the window it owns.
///
/// **Derived from the frames the guest actually owns**, not from a literal, so it cannot name a page
/// outside what the emitter maps for it. `guest.dts` carries the same range as a `reserved-memory`
/// child with `no-map`, and `xtask` rewrites it per guest.
const fn dma_pad_ipa(slot: usize) -> u64 {
    guest_ram_base(slot) + stage2::LINUX_SUP_FRAMES_PER_GUEST * stage2::SUP_FRAME_BYTES
        - DMA_PAD_SIZE
}

/// **The pad must sit above every blob loaded into the window**, or seeding it would overwrite a
/// guest's kernel, DTB or initramfs — which is precisely the failure the pad exists to make
/// impossible. Checked for both guests, because the arithmetic is per-slot.
const _: () = {
    let mut slot = 0;
    while slot < NUM_GUESTS {
        assert!(
            dma_pad_ipa(slot) > initrd_addr(slot)
                && dma_pad_ipa(slot) > dtb_addr(slot)
                && dma_pad_ipa(slot) > kernel_entry(slot),
            "the DMA landing pad overlaps a blob loaded into that guest's window"
        );
        assert!(
            dma_pad_ipa(slot) + DMA_PAD_SIZE
                == guest_ram_base(slot)
                    + stage2::LINUX_SUP_FRAMES_PER_GUEST * stage2::SUP_FRAME_BYTES,
            "the DMA landing pad does not end at the top of that guest's window"
        );
        slot += 1;
    }
};

/// What EL2 writes into every pad before the guests run, and expects to read back unchanged at
/// power-off. Distinct from `dmawitness`'s own sentinel so a log naming one cannot be mistaken for
/// the other.
const DMA_PAD_SENTINEL: u64 = 0xBADD_A7A0_BADD_A7A0;

/// Whether guest `slot`'s pad was found to be mapped, seeded, and read back at seeding time.
static DMA_PAD_SEEDED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// The physical address guest `slot`'s pad resolves to **through that guest's own live Stage-2
/// image** — `None` if its image maps nothing there.
///
/// Walked rather than assumed. These guests are identity-mapped today, so the answer equals the IPA;
/// taking that for granted would make the witness a statement about a coincidence of this layout
/// rather than about the map the guest actually runs under.
fn dma_pad_pa(slot: usize) -> Option<u64> {
    let l1 = hv_s2::arm64::vttbr_table(VTTBR.at(slot).load(Ordering::Relaxed));
    stage2::walk_stage2(l1, dma_pad_ipa(slot)).map(|r| r.pa)
}

/// **⑲-3a — write the sentinel into every guest's pad, before any guest runs.**
///
/// Called after `VTTBR` holds both images (the walk needs them) and before the first `eret` (so the
/// write cannot race a kernel). Halts rather than continuing on any failure: a pad that is unmapped,
/// or that does not read back what was just written to it, makes the power-off check vacuous, and a
/// vacuous witness that prints `OK` is worse than no witness.
fn seed_dma_pads(uart: &mut Pl011) {
    for slot in 0..NUM_GUESTS {
        let ipa = dma_pad_ipa(slot);
        let Some(pa) = dma_pad_pa(slot) else {
            let _ = writeln!(
                uart,
                "baleen: dmapad FAIL: dom {} maps nothing at its landing pad {ipa:#x}, so \
                 'the kernel never wrote here' would be a claim about an address that does not \
                 exist in its image; halting",
                slot_dom(slot)
            );
            crate::park();
        };
        // SAFETY: `pa` is a Stage-2 leaf's output address, obtained by decoding the descriptors this
        // hypervisor itself emitted for `slot`, so it names ordinary DRAM inside that guest's window;
        // EL2 is identity-mapped and no guest is running yet. Aliases no Rust object — guest RAM is
        // reached only through raw addresses.
        unsafe { core::ptr::write_volatile(pa as *mut u64, DMA_PAD_SENTINEL) };
        // SAFETY: as above, read-only.
        let back = unsafe { core::ptr::read_volatile(pa as *const u64) };
        if back != DMA_PAD_SENTINEL {
            let _ = writeln!(
                uart,
                "baleen: dmapad FAIL: dom {}'s landing pad {ipa:#x} (PA {pa:#x}) read back \
                 {back:#x} immediately after being seeded with {DMA_PAD_SENTINEL:#x} — the pad is \
                 not plain writable memory, so nothing later can be concluded from its contents; \
                 halting",
                slot_dom(slot)
            );
            crate::park();
        }
        DMA_PAD_SEEDED.at(slot).store(1, Ordering::Relaxed);
    }
}

/// **⑲-3b's witness — a bus master confined by a real guest's proven map, ACROSS GUEST EXECUTION.**
///
/// Closes honest-ledger item 2(b). Every DMA result before this one — SMMU rungs 1–4, ⑲-2, and
/// ⑲-3a's own seeding — was taken with the machine quiesced around the device.
///
/// ⚠ **The claim is "in flight across guest execution", NOT wall-clock concurrency**, and the
/// difference is real on this machine: one pCPU, TCG, and an engine that completes on a virtual-clock
/// timer between translation blocks. No guest instruction is mid-execution at the instant the copy
/// happens. What is established is that the machine was not stopped around the transfer.
///
/// Each arm asserts the same three-part progress conjunction, because a count alone is weak:
/// * **exits** — entries to EL2 from a guest while the transfer was outstanding;
/// * **ELR moved** — the exiting PC differed from the previous exit's, so instructions ran between
///   them. A guest wedged retaking one trap would produce exits without this;
/// * **both guests** — "no vCPU runs while the device DMAs" is refuted hardest by two having run.
///
/// ★ **And the binding is DERIVED, not written.** ⑲-2 pokes an STE; that cannot survive here, because
/// SMMU rung 4b re-derives the whole stream table from the model's device→domain relation after every
/// dispatch. The probe that found this measured the transfer aborting with its sentinel untouched.
/// So the confinement is established by one `DeviceAssign` and then **re-established from the model
/// tens of thousands of times while the guests ran** — rung 4b's thesis, finally load-bearing.
#[cfg(feature = "smmu")]
fn report_dma_inflight(uart: &mut Pl011) {
    let phase = flight::PHASE.load(Ordering::Relaxed);
    let (k1, l1) = (
        flight::KICK1.load(Ordering::Relaxed),
        flight::LAND1.load(Ordering::Relaxed),
    );
    let (k2, r2) = (
        flight::KICK2.load(Ordering::Relaxed),
        flight::RETIRE2.load(Ordering::Relaxed),
    );
    let permitted_span = l1.saturating_sub(k1);
    let refused_span = r2.saturating_sub(k2);
    let p1 = flight::EXITS_PERMITTED.at(SLOT_A).load(Ordering::Relaxed);
    let p2 = flight::EXITS_PERMITTED.at(1).load(Ordering::Relaxed);
    let r1g = flight::EXITS_REFUSED.at(SLOT_A).load(Ordering::Relaxed);
    let r2g = flight::EXITS_REFUSED.at(1).load(Ordering::Relaxed);
    let mp = flight::ELR_MOVES_PERMITTED.load(Ordering::Relaxed);
    let mr = flight::ELR_MOVES_REFUSED.load(Ordering::Relaxed);
    let peer_intact = flight::PEER_INTACT.load(Ordering::Relaxed) == 1;
    let (ev_kind, ev_sid, ev_addr) = (
        flight::EV_KIND.load(Ordering::Relaxed),
        flight::EV_SID.load(Ordering::Relaxed),
        flight::EV_ADDR.load(Ordering::Relaxed),
    );
    let sid = flight::SID.load(Ordering::Relaxed);
    let vacuous = flight::LANDED_AT_KICK.load(Ordering::Relaxed) != 0;

    let ok = phase == 5
        && !vacuous
        && l1 > k1
        && permitted_span >= FLIGHT_EXIT_FLOOR
        && refused_span >= FLIGHT_EXIT_FLOOR
        && mp >= 2
        && mr >= 2
        && p1 > 0
        && p2 > 0
        && r1g > 0
        && r2g > 0
        && peer_intact
        && ev_sid == sid
        // MEASURED, and both are sharper than "an event happened". `F_TRANSLATION` is the
        // *translation* fault class — the walk of this guest's own table refused the address —
        // rather than a configuration fault such as `C_BAD_STE`, which would mean the stream was
        // never properly bound and would make the whole arm a statement about broken setup. And the
        // recorded address is the one the device put on the bus, which is the sharpest attribution
        // the SMMU can give (design-lesson #70(d)): "the peer's site is unchanged" becomes "the SMMU
        // refused exactly this address".
        && ev_kind == u64::from(crate::smmu::EVT_F_TRANSLATION)
        && ev_addr == flight::PEER_IPA.load(Ordering::Relaxed);

    if ok {
        let _ = writeln!(
            uart,
            "baleen: dmaflight OK: a bus master confined by a REAL guest's own DERIVED Stage-2 \
             binding, IN FLIGHT ACROSS GUEST EXECUTION — the permitted transfer to {:#x} was kicked \
             at exit {k1} with its target untouched and landed by exit {l1}, {permitted_span} \
             entries to EL2 later, {p1} of them from dom {} and {p2} from dom {} with the guest PC \
             moving on {mp} of them; the SAME device then asked for {:#x} in the PEER's window and \
             was REFUSED across a further {refused_span} entries ({r1g}/{r2g} per guest, {mr} PC \
             moves), the SMMU logging kind {ev_kind:#x} for StreamID {ev_sid} at {ev_addr:#x} and \
             the peer's landing site intact. The stream table was never written by this code: one \
             DeviceAssign, then re-derived from the model on every one of those dispatches \
             (in flight across guest execution — NOT wall-clock concurrency; see this function's docs)",
            flight::OWN_IPA.load(Ordering::Relaxed),
            slot_dom(SLOT_A),
            slot_dom(1),
            flight::PEER_IPA.load(Ordering::Relaxed),
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: dmaflight FAIL: phase={phase} landed_at_kick={vacuous} kick1={k1} land1={l1} \
             permitted_span={permitted_span} kick2={k2} retire2={r2} refused_span={refused_span} \
             exits_permitted={p1}/{p2} exits_refused={r1g}/{r2g} elr_moves={mp}/{mr} \
             peer_intact={peer_intact} event=(kind {ev_kind:#x}, sid {ev_sid}, addr {ev_addr:#x}) \
             expected_sid={sid} floor={FLIGHT_EXIT_FLOOR}"
        );
    }
}

/// **⑲-3a's witness — the reserved pad is byte-for-byte what EL2 left in it.**
///
/// Every guest ran a whole Linux boot to userspace and powered off; this reads back the sentinel
/// seeded before any of them started. Asserted for EVERY slot, including a faulted one: unlike the
/// per-guest counters `witnesses_assertable` guards, a stopped kernel makes this claim *easier*
/// rather than legitimately zero, so there is nothing here that a retirement could excuse.
///
/// ⚠ **The ceiling, stated because it is the whole difference between this and a lucky boot:** a
/// surviving sentinel is consistent with the kernel never having reached the top of a 448 MiB
/// window. What upgrades it from luck to a reservation is the guest's OWN log line for the
/// `reserved-memory` node, which `xtask` asserts as a marker — Linux saying it saw the range and
/// mapped nothing there. Neither half is sufficient; the pair is.
/// ⚠ **The scrub's maintenance stride, MEASURED rather than assumed.**
///
/// `scrub_frame` strides `dc civac` across a freed frame. A stride **larger** than the core's
/// minimum data-cache line **skips lines**, leaving a dead tenant's data behind — so the number is
/// isolation-relevant, and it used to be a constant justified as *"64 bytes on every AArch64 core
/// this targets"*. It is now `min(64, CTR_EL0.DminLine)`, and this marker is what makes the value
/// visible on whatever platform is actually running rather than asserted about a target set.
///
/// Reported, not asserted against a fixed number: a core with a finer line is CORRECT here (the
/// stride simply gets finer), so pinning 64 would fail a machine this code handles properly.
///
/// ⚠ **Since A2 this number governs FOUR maintenance loops, not one**, and the marker's wording
/// still names only the frame scrub. That is deliberate rather than stale: the scrub is the loop
/// whose stride is *isolation-relevant* (a skipped line leaves a dead tenant's data behind), and it
/// is the loop #169 was found in. The others — the SMMU's structures, its event queue, the DMA
/// witness's sentinels — take the same measurement from `crate::cache`, so a wrong value would be
/// wrong in all four and this marker would show it.
fn report_scrub_line(uart: &mut Pl011) {
    let bytes = crate::cache::line_bytes();
    let _ = writeln!(
        uart,
        "baleen: scrubline OK: the frame-scrub maintenance loop strides {bytes} bytes, taken as \
         min(64, CTR_EL0.DminLine) on this machine — a stride WIDER than the true line would skip \
         lines and leave a dead tenant's data behind, so it is measured, not assumed"
    );
}

fn report_dma_pad(uart: &mut Pl011) {
    let mut ok = true;
    for slot in 0..NUM_GUESTS {
        let ipa = dma_pad_ipa(slot);
        let seeded = DMA_PAD_SEEDED.at(slot).load(Ordering::Relaxed);
        let Some(pa) = dma_pad_pa(slot) else {
            let _ = writeln!(
                uart,
                "baleen: dmapad FAIL: dom {}'s image no longer maps its landing pad {ipa:#x}",
                slot_dom(slot)
            );
            ok = false;
            continue;
        };
        // SAFETY: as `seed_dma_pads`; read-only, and every guest has stopped by now.
        let held = unsafe { core::ptr::read_volatile(pa as *const u64) };
        if seeded != 1 || held != DMA_PAD_SENTINEL {
            let _ = writeln!(
                uart,
                "baleen: dmapad FAIL: dom {}'s reserved landing pad {ipa:#x} (PA {pa:#x}) holds \
                 {held:#x}, not the {DMA_PAD_SENTINEL:#x} EL2 seeded before any guest ran \
                 (seeded={seeded}) — a kernel wrote inside a range its own device tree reserved \
                 no-map",
                slot_dom(slot)
            );
            ok = false;
        }
    }
    if ok {
        let _ = writeln!(
            uart,
            // ⚠ **"every guest booted an unmodified Linux to userspace" was FALSE the moment a slot
            // stopped running Linux**, and nothing caught it: this is not a forbidden marker, so the
            // `monitor` boot printed the sentence and passed. Found by reading the transcript, which
            // is where this class keeps being found. The claim is now the one the check actually
            // makes — nobody wrote the pad — and the reason each guest did not is stated per
            // payload, because for a kernel it is a device-tree reservation being honoured and for
            // the monitor there is no device tree at all.
            "baleen: dmapad OK: every partition powered off without writing one byte of the {} KiB \
             at the top of its own window (dom {} — {} — pad {:#x}; dom {} — {} — pad {:#x}; both \
             still holding the {DMA_PAD_SENTINEL:#x} EL2 left there before the first eret) — a DMA \
             landing here disturbs nothing a guest can observe",
            DMA_PAD_SIZE / 1024,
            slot_dom(SLOT_A),
            payload_kind(SLOT_A),
            dma_pad_ipa(SLOT_A),
            slot_dom(SLOT_B),
            payload_kind(SLOT_B),
            dma_pad_ipa(SLOT_B),
        );
    }
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

    // ㉗ — **the grant, and its position here is a CORRECTION the machine made.**
    //
    // The scope for this rung put it between the two guests' builds, reasoning that `GrantAccess`
    // names a frame the grantor must already own. That is true and it is not sufficient: the call
    // also requires the **GRANTEE** to be alive, and the monitor's domain does not exist until the
    // `DomainCreate` immediately above. The first boot said `NotAlive` and named the caller, which
    // read like a grantor problem and was a grantee one.
    //
    // ★ So the only correct home is *inside the grantee's build, after it exists and before it links
    // anything* — which is also where it reads best, one statement above the link it authorizes.
    //
    // ⚠ **Issued AS GUEST A (`go` takes the caller), which is the integrator authorizing the read
    // rather than a cheat.** Every model call here is already dispatched on a guest's behalf, and an
    // unmodified Linux kernel issues no baleen hypercalls at all — a deployment's static
    // configuration is the only place this authorization could come from. ★ That is the right shape
    // for mixed criticality: **the untrusted partition never had a say in whether it is watched.**
    #[cfg(feature = "monitor")]
    if !runs_linux(set) {
        go(
            GUEST_A,
            HvCall::GrantAccess {
                gref: OBSERVE_GREF,
                grantee: guest,
                frame: OBSERVED_FRAME,
                // ★ The narrowness is load-bearing: `p2m_link` accepts a foreign child only with a
                // grant of matching permission, so a read-only grant leaves a WRITABLE leaf
                // unauthorized. The monitor cannot widen its own view by asking for more.
                readonly: true,
            },
            "grant the monitor a read-only view of the policy partition",
        );
    }

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
            // ㉗ — **the one slot that does not hold one of this guest's own frames.** The monitor
            // trades its frame at `VACATED_OFFSET` for a read-only leaf onto the policy partition's.
            // Written here, inside the ordinary link loop, rather than as a patch afterwards: the
            // slot must be *taken* by the foreign edge, and a second pass that overwrote a populated
            // slot would be a different (and much less obvious) operation than never filling it.
            #[cfg(feature = "monitor")]
            if !runs_linux(set) && offset == VACATED_OFFSET {
                go(
                    guest,
                    HvCall::P2mLink {
                        parent: table,
                        slot,
                        child: OBSERVED_FRAME,
                        // ★ The whole rung is this `false`. `p2m_link` accepts a foreign child only
                        // with a matching grant, and the emitter turns a non-writable leaf into
                        // `S2AP=RO` — so "observe without influence" is the model's own vocabulary,
                        // not a new concept.
                        writable: false,
                        leaf: true,
                        // Not executable: the monitor reads its peer's memory, it never runs it.
                        execute: false,
                    },
                    "link the monitor's read-only view of its peer",
                );
                continue;
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
    // ㉗ — said AFTER the loop, not inside it: `go` holds `uart` for the whole link pass. One
    // summary line beats a message buried among 224 links anyway.
    #[cfg(feature = "monitor")]
    if !runs_linux(set) {
        let _ = writeln!(
            uart,
            "baleen: observe: dom {guest} spent its own frame at window offset {VACATED_OFFSET} \
             (2 MiB its payload does not need) on a READ-ONLY leaf onto dom {}'s frame \
             {OBSERVED_FRAME} — so it links {} of its own instead of {}. The leaf is emitted by the \
             PROVEN emitter from an authorized grant; nothing here writes a descriptor",
            slot_dom(SLOT_A),
            stage2::LINUX_SUP_FRAMES_PER_GUEST - 1,
            stage2::LINUX_SUP_FRAMES_PER_GUEST
        );
    }

    stage2::build_stage2_from_p2m(hv, guest, set)
}

/// ㉗ — **the monitor faulted on its own observation window**, which is either the kill-probe
/// working or the rung broken, and the two are distinguished by one bit.
///
/// **A WRITE (`wnr`) is the expected outcome and the point of the probe:** the view is `S2AP=RO`, so
/// the hardware refuses the store, EL2 records it, and the guest is resumed past the instruction.
/// `report_disjointness` asserts the descriptor says read-only; this asserts the *hardware acts on
/// it*, which is a different claim and the one a safety argument actually needs — a permission bit
/// nothing ever tested is a permission bit that could have been decoded wrong.
///
/// **A READ here is a FAILURE and halts.** The whole rung is that the monitor can read this frame
/// without a hypercall; a read that faults means the leaf is missing, and a monitor that cannot see
/// is the exact condition #193 spent a rung making impossible.
#[cfg(feature = "monitor")]
fn handle_observation_fault(
    faulting: usize,
    ipa: u64,
    write: bool,
    _frame: &mut LinuxFrame,
    uart: &mut Pl011,
) {
    if !write {
        let _ = writeln!(
            uart,
            "baleen: observe FAIL: dom {} took a READ fault at IPA 0x{ipa:08x} inside its own \
             observation window — the read-only leaf is missing, so the monitor is blind; halting",
            slot_dom(faulting)
        );
        crate::park();
    }
    let n = OBSERVE_WRITES_REFUSED.fetch_add(1, Ordering::Relaxed) + 1;
    if n == 1 {
        let _ = writeln!(
            uart,
            "baleen: observe OK: dom {} stored through its read-only view at IPA 0x{ipa:08x} and \
             the HARDWARE refused it — a Stage-2 permission fault, taken at EL2, resumed past. The \
             channel is one-way in the only sense that matters: not because the monitor is trusted \
             not to write, but because the write does not land",
            slot_dom(faulting)
        );
    }
    // Resumed, exactly as the peer-fault negative test is: the probe is part of the payload's normal
    // execution, not a fatal event.
    crate::guest::advance_elr_past_fault();
}

/// How many stores the monitor made through its read-only view that the hardware refused.
///
/// A plain atomic, not a [`crate::cell::BootCell`]: written from an EL2 exception handler, which is
/// `crate::cell`'s class-3 hazard and has no borrow to overlap.
#[cfg(feature = "monitor")]
static OBSERVE_WRITES_REFUSED: AtomicU64 = AtomicU64::new(0);

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
    // ㉗ — the two deliberate exceptions, both counted so the report states them as facts rather
    // than tolerating them as silence. `observed` is the authorized read-only view; `vacated` is the
    // monitor's own frame that it gave up to make room for it.
    #[cfg(feature = "monitor")]
    let (mut observed, mut vacated) = (0u64, 0u64);

    for m in 0..stage2::NUM_SUP_FRAMES {
        let ipa = stage2::LINUX_RAM_BASE + m * stage2::SUP_FRAME_BYTES;
        let mine_is_a = m < per;
        let ra = stage2::walk_stage2(l1_a, ipa);
        let rb = stage2::walk_stage2(l1_b, ipa);

        // ㉗ — **the authorized view, checked before the disjointness arms and asserted HARDER than
        // they are.** This frame is guest A's, and it IS reachable from the monitor's image: that is
        // the rung. What must hold is that the reach is exactly the one that was authorized —
        // identity-mapped (the emitter maps `IPA(m) -> PA(m)`, and a view landing anywhere else
        // would be a translation defect wearing the rung's clothes) and **READ-ONLY**.
        //
        // ★ `perm` is read here for the first time in this walk. Until ㉗ the report checked only
        // *reachability* — which is exactly why the rung is a strengthening and not merely a
        // weakening: the one frame that is now shared is the one frame whose PERMISSION is asserted.
        #[cfg(feature = "monitor")]
        if m == u64::from(OBSERVED_FRAME) {
            match rb {
                Some(reach) if reach.pa == ipa && !reach.writable() && reach.xn => observed += 1,
                other => {
                    let _ = writeln!(
                        uart,
                        "baleen: observe FAIL: dom {}'s view of dom {}'s frame {m} (IPA \
                         0x{ipa:08x}) is not the authorized one — expected an identity-mapped, \
                         read-only, execute-never leaf, got {other:?}",
                        slot_dom(MONITOR_SLOT),
                        slot_dom(SLOT_A)
                    );
                    crate::park();
                }
            }
            // Guest A's own reach at this frame is still asserted by the loop below; only the
            // monitor's arm is answered here.
            match ra {
                Some(reach) if reach.pa == ipa => a_own += 1,
                _ => {
                    let _ = writeln!(
                        uart,
                        "baleen: peer FAIL: frame {m} (IPA 0x{ipa:08x}) did not resolve to its own \
                         identity mapping in its owner's image"
                    );
                    crate::park();
                }
            }
            continue;
        }

        // ㉗ — the frame the monitor GAVE UP. Unmapped in both images, and that is correct rather
        // than a hole to tolerate: nobody allocated it, so no domain owns it and the emitter has
        // nothing to map. Counted and named, because an unmapped frame inside a guest's own window
        // would otherwise hit the `_ =>` arm below and PARK the boot on a hole it was told to make.
        #[cfg(feature = "monitor")]
        if m == u64::from(first_frame(MONITOR_SLOT)) + VACATED_OFFSET {
            if rb.is_none() && ra.is_none() {
                vacated += 1;
                continue;
            }
            let _ = writeln!(
                uart,
                "baleen: observe FAIL: the frame dom {} gave up (frame {m}, IPA 0x{ipa:08x}) is \
                 still mapped somewhere — dom {} {:?}, dom {} {:?}; the slot was supposed to be \
                 spent on the peer view",
                slot_dom(MONITOR_SLOT),
                slot_dom(SLOT_A),
                ra,
                slot_dom(MONITOR_SLOT),
                rb
            );
            crate::park();
        }

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

    // ㉗ — the monitor owns one fewer frame than its peer, having spent the slot on the view.
    #[cfg(feature = "monitor")]
    let b_expected = per - 1;
    #[cfg(not(feature = "monitor"))]
    let b_expected = per;

    // ⚠⚠ **㉗'s two counters are ASSERTED, not merely printed, and that is not a formality.** The
    // success line says "gave up 1 … reaches EXACTLY 1", and both numbers come from branches
    // reached only if their frame index falls where this code thinks it does. Without this check an
    // `OBSERVED_FRAME` outside the walked range — or a `VACATED_OFFSET` that stopped matching —
    // would leave the counter at **0**, and the boot would cheerfully print *"reaches EXACTLY 0 of
    // dom 1's"* under a green `peer OK`. That is #275's shape ("found nothing" and "nothing is
    // wrong" are the same output), inside the rung whose entire subject is one frame.
    //
    // ★ Kill-probed (probe 5): disabling the observed-frame branch reddens the boot.
    #[cfg(feature = "monitor")]
    let channel_ok = observed == 1 && vacated == 1;
    #[cfg(not(feature = "monitor"))]
    let channel_ok = true;

    if a_own == per && b_own == b_expected && a_peer == 0 && b_peer == 0 && channel_ok {
        #[cfg(not(feature = "monitor"))]
        let _ = writeln!(
            uart,
            "baleen: peer OK: two domains, two Stage-2 images, DISJOINT over the guest-RAM window \
             — dom {GUEST_A} reaches its {a_own} frames and 0 of dom {GUEST_B}'s; dom {GUEST_B} \
             reaches its {b_own} and 0 of dom {GUEST_A}'s; and neither maps hv-metal's memory or \
             any window outside guest RAM ({} frames + 3 out-of-window probes, walked from the \
             emitted descriptors)",
            stage2::NUM_SUP_FRAMES
        );
        // ⚠⚠ **A DIFFERENT SENTENCE, NOT A QUALIFIED ONE.** The shipped boot's claim is "DISJOINT",
        // full stop, and ㉗'s is not that claim with an asterisk — it is a narrower claim about a
        // machine with an authorized channel in it. Printing the old sentence plus a footnote is how
        // a reader ends up quoting the strong half of a weakened guarantee, so this configuration
        // says its own thing and the word DISJOINT does not appear in it.
        #[cfg(feature = "monitor")]
        let _ = writeln!(
            uart,
            "baleen: peer OK: two domains, two Stage-2 images, disjoint over the guest-RAM window \
             EXCEPT FOR ONE AUTHORIZED, READ-ONLY FRAME — dom {GUEST_A} reaches its {a_own} frames \
             and 0 of dom {GUEST_B}'s (the policy partition is unaware it is watched, and cannot \
             reach the monitor at all); dom {GUEST_B} reaches its own {b_own}, gave up {vacated} to \
             make room, and reaches EXACTLY {observed} of dom {GUEST_A}'s — identity-mapped, S2AP=RO \
             and execute-never, asserted from the descriptor. Neither maps hv-metal's memory or any \
             window outside guest RAM ({} frames + 3 out-of-window probes, walked from the emitted \
             descriptors)",
            stage2::NUM_SUP_FRAMES
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: peer FAIL: the two images are not as this configuration expects — dom \
             {GUEST_A} own={a_own} peer={a_peer}, dom {GUEST_B} own={b_own} peer={b_peer} \
             (expected dom {GUEST_A} own={per}, dom {GUEST_B} own={b_expected}, peer=0)"
        );
        // ㉗ — a SECOND line rather than an interpolated clause, because `no_std` has no cheap way
        // to build one conditionally. ★ It earns its keep: probe 5 showed the line above reporting
        // `peer=1`, which reads as an ISOLATION failure and sends a reader to debug the emitter,
        // while the real cause was `observed=0` — the channel's frame never walked. A shared
        // diagnostic for two unrelated failure modes misdirects on at least one of them.
        #[cfg(feature = "monitor")]
        let _ = writeln!(
            uart,
            "baleen: peer FAIL: the observation channel counted observed={observed} \
             vacated={vacated} (expected 1 and 1) — a zero here means the frame the channel is \
             built on was never walked, not that the images disagree"
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

// ─── ⑱-1: the identity EL2 gives a guest ─────────────────────────────────────────────────────────
//
// A guest's `MRS x, MPIDR_EL1` at EL1 does not read `MPIDR_EL1`. It reads **`VMPIDR_EL2`**, and
// likewise `MIDR_EL1` reads `VPIDR_EL2` — the two registers that exist so a hypervisor can tell a
// guest *which CPU it is on* rather than leaking the physical one. hv-metal wrote neither.
//
// **Both are architecturally UNKNOWN at reset** (Arm ARM D19, `VMPIDR_EL2`/`VPIDR_EL2`), so until
// this rung the identity every guest read was whatever the implementation happened to leave behind.
// **MEASURED on QEMU 11.0.3:** `VMPIDR_EL2 = 0x80000000 = MPIDR_EL1` and `VPIDR_EL2 = 0x410fd083 =
// MIDR_EL1` — i.e. QEMU resets them to the physical values, which are exactly the values the guests'
// device trees describe. So the identity was correct here **by the implementation's reset choice,
// and by nothing hv-metal did**: design-lesson #127's shape, one level below the workload.
//
// ⚠ **State the scope honestly.** `main.rs` parks any CPU whose `MPIDR` affinity is non-zero, so
// hv-metal only ever runs where the physical affinity is 0 — this is therefore *not* a latent bug on
// a big.LITTLE board, because such a board would not get this far. What it is: a value the
// architecture leaves unspecified, on which a guest's ability to match its own boot CPU against its
// device tree depends. An implementation resetting `VMPIDR_EL2` to anything else gives both guests an
// identity their own `cpu@0 { reg = <0x00>; }` does not describe, and arm64 Linux refuses that.
//
// **What this rung changes is WHERE the answer comes from**, not what it is: the value is now a
// function EL2 evaluates. That is also what ⑱-3 needs — with two vCPUs per guest the identity stops
// being constant, and the difference between "EL2 computes it" and "the reset left it" is the
// difference between changing an argument and discovering a missing register.
//
// ## ★ THE KILL PROBE, and it came back GUEST-OBSERVED
//
// A write nobody reads is decoration (design-lesson #111), and the read-back below cannot tell the
// difference — it would pass just as well if `VMPIDR_EL2` served no guest at all. So the write was
// corrupted deliberately: `Aff0 = the guest's SLOT` instead of `Aff0 = the vCPU index`, which leaves
// dom 1 (slot 0) untouched and gives dom 2 an MPIDR of 1 that its own `cpu@0 { reg = <0x00>; }` does
// not describe. **MEASURED:**
//
// | guest | value | result |
// |---|---|---|
// | dom 1 | unchanged | booted to userspace, `BALEEN-STEP0-OK`, powered off normally |
// | dom 2 | `Aff0 = 1` | `missing boot CPU MPIDR, not enabling secondaries` → **`Kernel panic - not syncing: Attempted to kill the idle task!`** |
//
// dom 2 QUOTED ITS OWN MPIDR MISMATCH and died of it. That is the register reaching a guest and the
// guest acting on it — evidence the read-back cannot give, from the side of the seam EL2 does not
// own. The differential is what makes it conclusive: the guest whose value changed died, the guest
// whose value did not, did not.

/// `MPIDR_EL1` bit 31 — RES1 in every ARMv8 implementation, so a computed MPIDR must carry it.
const MPIDR_RES1: u64 = 1 << 31;

/// The mask arm64 Linux applies (`MPIDR_HWID_BITMASK`) before matching a CPU's MPIDR against a
/// device tree `reg`: `Aff3:Aff2:Aff1:Aff0`, i.e. everything except the RES1/U/MT flag bits.
const MPIDR_HWID_BITMASK: u64 = 0xff_00ff_ffff;

/// The `MPIDR_EL1` a guest's vCPU reads — **`Aff0` is the vCPU's index within its own guest.**
///
/// **A function of the vCPU, deliberately NOT of the guest slot.** Every guest is its own machine and
/// every guest's `guest.dts` says `cpu@0 { reg = <0x00>; }`, so dom 1's and dom 2's first vCPUs must
/// read the *same* MPIDR. Taking a [`Incoming`] here would say the opposite; a bare index is right
/// because there is exactly one subject, which is the same reason [`PerGuest::at`] takes one.
///
/// **`U` (bit 30, "uniprocessor system") is deliberately left clear**, matching the value the guests
/// already read. Setting it would be defensible at one vCPU and wrong at two, and it would make this
/// rung change what a guest sees — which would cost the structural witness below its meaning.
///
/// ## ★ ⑱-3b-i — THE AFFINITY WAS DERIVED TWICE, AND A DOC SAID IT WAS DERIVED ONCE
///
/// This function used to compute `MPIDR_RES1 | (vcpu as u64)` itself. Meanwhile
/// [`hv_vdev::gicv3::vcpu_affinity`] — which the emulated `GICR_TYPER` reports — carries this in
/// **bold** at the top of its own doc: *"The affinity a vCPU has, and the ONE place that answer is
/// derived … so `hv-metal` calls this rather than repeating it — design-lesson #74."*
///
/// **`hv-metal` did not call it.** There were two derivations of the mapping, in two crates, one of
/// which asserted in the crate `hv-verify` can reach that there was one. They agreed — because at
/// the time the only vCPU index in existence **was** `0`, and every encoding of the identity agrees
/// at a single point. ⑱-3b-ii raised `VCPUS_PER_GUEST` to 2, so that coincidence is gone and the
/// single derivation below is now doing real work rather than being tidy.
///
/// **This is not a tidy-up, and the guest is what makes it load-bearing.** arm64 Linux's
/// `gic_populate_rdist` walks the redistributors looking for the frame whose affinity equals its own
/// `MPIDR_EL1`, and **fails the CPU if none does** — so the guest matches the two artifacts against
/// each other on every boot. Two encodings diverge the first time anyone gives the affinity levels
/// structure (`Aff1 = vcpu / 4`, say, for a cluster topology), and the failure is ⑱-1's already
/// measured one: `missing boot CPU MPIDR, not enabling secondaries` → `Kernel panic`. Design-lesson
/// #74 exactly, with a doc pointing the wrong way.
///
/// The two placements compose rather than coincide, which is what makes one derivation *correct*
/// here and not merely shorter: `vcpu_affinity` returns `Aff3:Aff2:Aff1:Aff0` packed one byte per
/// level with `Aff0` at bit 0, which is where `MPIDR_EL1` wants it and which `GICR_TYPER` shifts to
/// bit 32.
const fn guest_mpidr(vcpu: VcpuIdx) -> u64 {
    MPIDR_RES1 | vcpu_affinity(vcpu.get())
}

// ⑱-3a: `BOOT_VCPU` and `VCPUS_PER_GUEST` moved to `crate::role`, which owns the vCPU axis and so
// should own its count. Every use below is imported from there; the pairing assert moved with them.
//
// ⑱-3b-i: **`BOOT_VCPU` then stopped being importable at all.** Moving it was right and was not
// enough — this file went on naming it at six sites where the vCPU that mattered was the *running*
// one, and at one vCPU per guest no build, gate or reviewer can tell those from the three that
// really mean the boot vCPU. It is private to `crate::role` now, reachable only as
// `VcpuIdx::boot()`, and every other site takes its index from a role. See `crate::role::VcpuIdx`.

// `guest.dts` gives `cpu@0` `reg = <0x00>`, and arm64 Linux matches its boot CPU by comparing
// `MPIDR_EL1 & MPIDR_HWID_BITMASK` against that. Two derivations of one fact (⑭'s defect), pinned:
// if `guest_mpidr` ever stops agreeing with the device tree the build stops, instead of the guest
// booting to `Bad CPU number`.
const _: () = assert!(
    guest_mpidr(VcpuIdx::boot()) & MPIDR_HWID_BITMASK == 0,
    "guest.dts declares cpu@0 with reg = <0x00>; guest_mpidr(0) must present that same hwid"
);

// **⑱-3b-i — the hwid a guest reads IS the affinity its redistributor reports.**
//
// The assert above pins `guest_mpidr` against the *device tree*. This one pins it against the
// *emulated GIC*, which is the other artifact `gic_populate_rdist` compares it to — and the two
// comparisons are what a booting CPU actually performs. `MPIDR_EL1` places `Aff0` at bit 0 and
// `GICR_TYPER` at bit 32, so a single shared derivation is not by itself enough: the *placement*
// has to be right at both ends, and this is the end `hv-metal` owns.
//
// **Non-vacuous at one vCPU**, deliberately, because it is a statement about where the bits sit
// rather than about how many there are: it fails if `MPIDR_RES1` ever moves into the hwid field, if
// the mask clips the affinity, or if the two derivations are split apart again. The model's half —
// that `GICR_TYPER` really reports `vcpu_affinity` — is ⑱-2's Kani harness
// `the_typer_reports_the_vcpu_affinity`, so `vcpu_affinity` is the shared term and neither side
// restates the other.
//
// ⚠ **What is NOT asserted here: that DISTINCT vCPUs get distinct affinities**, which is what
// `gic_populate_rdist` needs to match the *right* redistributor rather than merely a well-formed
// one. It cannot be stated as anything but a vacuous truth while `VCPUS_PER_GUEST == 1`, and a
// vacuous assert that reads as coverage is worse than an absent one. It belongs to ⑱-3b-ii, with
// the rung that gives the axis a second value.
//
// ✅ **DISCHARGED BY ⑱-4b-ii — see `AFFINITIES_ARE_DISTINCT` below.** The obligation was recorded
// here, came due when ⑱-3b-ii raised `VCPUS_PER_GUEST` to 2, and was not paid then. This rung is
// what makes it load-bearing rather than merely non-vacuous, so it is paid here.
const _: () = assert!(
    guest_mpidr(VcpuIdx::boot()) & MPIDR_HWID_BITMASK == vcpu_affinity(VcpuIdx::boot().get()),
    "the affinity a guest reads in MPIDR_EL1 must be the one its redistributor reports in \
     GICR_TYPER — gic_populate_rdist matches them against each other and fails the CPU if they \
     disagree"
);

// ⑱-4b-ii: `MPIDR_RES1` must lie OUTSIDE the hwid field. Everything below reasons about
// `vcpu_affinity` where `guest_mpidr` is what the guest reads, and this is what makes the two
// interchangeable under the mask instead of that being a sentence in a comment.
const _: () = assert!(
    MPIDR_RES1 & MPIDR_HWID_BITMASK == 0,
    "MPIDR_RES1 must not fall inside MPIDR_HWID_BITMASK, or guest_mpidr's masked hwid would carry \
     a bit that vcpu_affinity — the value GICR_TYPER and the DTS both encode — does not"
);

// ⑱-4b-ii: the pin for `cpu@1`, the twin of the `cpu@0` one above.
//
// It names `vcpu_affinity` rather than `guest_mpidr` because [`VcpuIdx`] has no const constructor
// for a bare index — that is ⑱-3b-i's whole point — and the assert directly above makes the two
// equal under the mask. So this is still ONE derivation, reached from the only end a `const` can.
const _: () = assert!(
    vcpu_affinity(1) & MPIDR_HWID_BITMASK == 1,
    "guest.dts declares cpu@1 with reg = <0x01>; vcpu_affinity(1) must present that same hwid, or \
     PSCI CPU_ON's MPIDR inversion resolves the target Linux named to the wrong vCPU"
);

/// ★ **⑱-4b-ii — DISTINCT vCPUs GET DISTINCT AFFINITIES, ∀ pairs, at compile time.**
///
/// The obligation recorded above, now due and now load-bearing. [`cpu_on`] inverts the vCPU→MPIDR
/// map by **searching** — offering each of the guest's vCPUs to [`guest_mpidr`] and comparing under
/// [`MPIDR_HWID_BITMASK`]. A search returns *the* answer only if the map is injective; if two vCPUs
/// ever shared an affinity it would return whichever came first, and a guest asking to start CPU 1
/// could be given CPU 0 — or `ALREADY_ON` for a CPU that is not the one it named.
///
/// It is also what `gic_populate_rdist` needs: a booting secondary matches its own `MPIDR_EL1`
/// against each redistributor's `GICR_TYPER` affinity, and picks the first that matches.
///
/// Checked pairwise over the whole axis rather than for the two values that exist today, so raising
/// [`VCPUS_PER_GUEST`] cannot silently outgrow it. `vcpu_affinity` is the shared derivation, so this
/// constrains the same function the emulated GIC and the device tree are pinned against.
const fn affinities_are_distinct() -> bool {
    let mut i = 0;
    while i < VCPUS_PER_GUEST {
        let mut j = i + 1;
        while j < VCPUS_PER_GUEST {
            if vcpu_affinity(i) & MPIDR_HWID_BITMASK == vcpu_affinity(j) & MPIDR_HWID_BITMASK {
                return false;
            }
            j += 1;
        }
        i += 1;
    }
    true
}
const AFFINITIES_ARE_DISTINCT: bool = affinities_are_distinct();
const _: () = assert!(
    AFFINITIES_ARE_DISTINCT,
    "two vCPUs of one guest present the same hwid: PSCI CPU_ON's MPIDR inversion would be \
     ambiguous, and a booting secondary would match the wrong redistributor"
);

/// Times [`set_guest_identity`] ran, and times the registers **read back** as what it wrote.
/// Compared in [`report_guest_identity`]: a difference means the write did not take.
static IDENTITY_WRITES: AtomicU64 = AtomicU64::new(0);
static IDENTITY_VERIFIED: AtomicU64 = AtomicU64::new(0);
/// The last read-back of each register, so the witness can print the value rather than assert about
/// one nobody sees.
static IDENTITY_VMPIDR: AtomicU64 = AtomicU64::new(0);
static IDENTITY_VPIDR: AtomicU64 = AtomicU64::new(0);

/// Give the vCPU that is about to run the identity **EL2 chose for it**, and read both registers back.
///
/// Called from the two — and only two — places a vCPU reaches EL1: the boot `eret` into guest A, and
/// every [`switch_context`]. One derivation, two call sites (#74); guest A's boot entry is not a
/// second answer to "what identity does a vCPU get", it is the same function applied to the first one.
///
/// `VPIDR_EL2` is **read off the live CPU** rather than written from a literal, for the same reason
/// `sctlr_at_boot` is: the guest genuinely executes on this PE, so the MIDR it should see IS this
/// PE's, and a second encoding of that fact would agree only until the board changed.
///
/// No `isb` is needed: every path out of here reaches EL1 through an `eret`, which is a
/// context-synchronising event.
///
/// ## ★ ⑱-3b-i — it takes an [`Incoming`], and it used to take a constant
///
/// The parameter was a `usize` and **both** call sites passed `BOOT_VCPU`. On the boot `eret` that
/// is right. In [`switch_context`] it is right only while a guest has one vCPU, and the comment at
/// that call site had already said so — *"at ⑱-3 the answer stops being constant"* — which is the
/// interesting part: the hazard was **written down, in the right place, a rung in advance, and the
/// code still could not enforce it.** A note is not a mechanism.
///
/// So the parameter is the role. "The vCPU that is arriving on the pCPU" is exactly whose identity
/// this writes, at both call sites, including the boot one — guest A's first entry *is* an arrival,
/// which is why this is a narrowing rather than a special case. `set_guest_identity(VcpuIdx::boot())`
/// no longer typechecks, and `BOOT_VCPU` is no longer a name this file can resolve.
///
/// ⚠ It takes the [`Incoming`] for its **vCPU**, not its guest, and [`guest_mpidr`] still takes a
/// bare index for the reason its own doc gives: every guest's first vCPU reads the *same* MPIDR,
/// because every guest is its own machine. The role narrows where the index may come from without
/// making the value depend on the guest.
fn set_guest_identity(next: Incoming) {
    let mpidr = guest_mpidr(next.vcpu());
    let (midr, vmpidr_back, vpidr_back): (u64, u64, u64);
    // SAFETY: `VMPIDR_EL2`/`VPIDR_EL2` are RW at EL2 and `MIDR_EL1` is readable there; these are the
    // registers whose whole purpose is for a hypervisor to write. No memory effect.
    unsafe {
        asm!(
            "mrs {midr}, midr_el1",
            "msr vmpidr_el2, {mpidr}",
            "msr vpidr_el2, {midr}",
            "mrs {a}, vmpidr_el2",
            "mrs {b}, vpidr_el2",
            mpidr = in(reg) mpidr,
            midr = out(reg) midr,
            a = out(reg) vmpidr_back,
            b = out(reg) vpidr_back,
            options(nomem, nostack, preserves_flags),
        );
    }
    IDENTITY_VMPIDR.store(vmpidr_back, Ordering::Relaxed);
    IDENTITY_VPIDR.store(vpidr_back, Ordering::Relaxed);
    IDENTITY_WRITES.fetch_add(1, Ordering::Relaxed);
    // Both halves, against what was actually written — a read-back that only checked `VMPIDR_EL2`
    // would pass with `VPIDR_EL2` never written at all, which is the defect this rung closes.
    if vmpidr_back == mpidr && vpidr_back == midr {
        IDENTITY_VERIFIED.fetch_add(1, Ordering::Relaxed);
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
// (`crate::monitor` is spelled without an intra-doc link on purpose: the module exists only under
// `--features monitor`, and a link would be a broken one — `-D warnings` — in every other config.)
/// `pub(crate)` for `crate::monitor`: the bare-metal payload retires through the **same** FID a
/// Linux guest issues, so it takes the same handler and the same retirement path rather than a
/// second shutdown sequence that runs once and is never exercised again.
pub(crate) const PSCI_SYSTEM_OFF_FID: u64 = 0x8400_0008;
const PSCI_VERSION_1_1: u64 = 0x0001_0001;
const PSCI_NOT_SUPPORTED: u64 = (-1i64) as u64;
/// PSCI `CPU_ON`, SMC64. ⑱-4b-ii is the rung that answers it with anything but `NOT_SUPPORTED`.
/// `guest.dts`'s `psci` node has declared `cpu_on = <0xc4000003>` since the file was written.
const PSCI_CPU_ON_FID: u64 = 0xc400_0003;
/// The return codes ⑱-4b-ii can produce, taken from the PSCI spec's table rather than from what the
/// one caller we have happens to check: a guest given a wrong code makes a wrong decision about its
/// own CPUs, and the next caller may not be Linux.
const PSCI_SUCCESS: u64 = 0;
const PSCI_INVALID_PARAMETERS: u64 = (-2i64) as u64;
const PSCI_ALREADY_ON: u64 = (-4i64) as u64;
const PSCI_INVALID_ADDRESS: u64 = (-9i64) as u64;

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
static VGIC: BootCell<PerGuest<DeployedGic, NUM_GUESTS>> =
    BootCell::new("VGIC", PerGuest::new([GIC_AT_RESET; NUM_GUESTS]));

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
static TIMER_FORWARDED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// How many guest-generated SGIs EL2 has mediated and delivered (③-a2) — the second thing `IMO=1`
/// made EL2 responsible for. Same standing as [`TIMER_FORWARDED`]: written from a trap handler, so an
/// atomic rather than a [`BootCell`], and per guest for the same reason.
static SGIS_DELIVERED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// Forwarded timer interrupts EL2 could not place, because the guest's list-register bank was full.
///
/// **The last guest-reachable halt on this path, and it was reachable by four instructions.** A guest
/// that fills its four list registers with SGIs it never takes (mask interrupts, four
/// `ICC_SGI1R_EL1` writes) makes the next timer forward fail — and that used to `crate::park()`,
/// taking the peer domain down with it. Measured before the fix: `sgis_placed=4
/// timer_forward_refused=true`.
///
/// **Deferral, not retirement** (unlike the seven sites `fault_retire` handles): a guest that fills
/// its own bank has done nothing EL2 has no rule for. It is only harming itself — it is the one that
/// goes without a tick — and EL2's own `CNTHP` slice is untouched, so the peer keeps running either
/// way.
static TIMER_DEFERRED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// The vINTID the tick-deferral probe's Active filler entries carry. Never presented (Active, not
/// Pending), so the value only has to be distinctive in a register dump.
#[cfg(feature = "selftest")]
const TICK_PROBE_FILL_INTID: u32 = 200;

/// One-shot latch for the tick-deferral probe, so it perturbs exactly one timer interrupt.
#[cfg(feature = "selftest")]
static TICK_DEFER_PROBED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

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
///
/// **⑱-3a: one per vCPU, not per guest** — and III-1 is the reason for that too. Its own docs say a
/// shared set "would reopen the cross-vCPU leak 8b/III-3 closed"; the synthetic path has been
/// per-vCPU since, while this one was per-guest, which at one vCPU per guest is the same arrangement
/// by coincidence. At two it would let one vCPU drain its sibling's SGIs into its own list
/// registers. `PendingSet` declares only `PerVcpuState`, so the coincidence cannot come back.
static LINUX_PENDING: PerVcpu<crate::pending::PendingSet, NUM_GUESTS, VCPUS_PER_GUEST> =
    PerVcpu::new(
        [const { [const { crate::pending::PendingSet::new() }; VCPUS_PER_GUEST] }; NUM_GUESTS],
    );

/// vINTs that found no free list register and were recorded in the pending set instead.
static SGIS_DEFERRED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// ⑱-5 — **every `(SGI, target vCPU)` pair EL2 undertook to deliver.** One guest write can name
/// several vCPUs (a broadcast names every one but the sender), so this counts targets, not writes.
///
/// The witness is the identity `named == delivered + deferred + routed`: each such pair gets
/// **exactly one** disposition — into the running vCPU's list registers, into its pending set
/// because the bank was full, or into a *sibling's* set because that vCPU is not on the pCPU. There
/// is no fourth, so this is a property of the mechanism rather than of what any guest sends.
///
/// ⚠ **It counts DISPOSITIONS, not decodes, and the distinction was forced by the witness itself.**
/// The obvious wording — "pairs the `ICC_SGI1R_EL1` decode named" — was what this doc said first, and
/// it was wrong in the configuration the REQUIRED gate boots: the `selftest` overflow probe calls
/// [`deliver_or_defer_vint`] directly to manufacture a full bank, which is a disposition no decode
/// named. Counting at the decode left the identity one short and the marker went red on its first
/// run. **Counted where the disposition happens, it holds for every caller** — including callers
/// this rung did not think of, which is the point.
static SGI_TARGETS_NAMED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// ⑱-5 — SGIs marked for a vCPU that was **not the one running**, i.e. genuinely routed rather than
/// delivered. **Zero until ⑱-4 starts a second vCPU**, and reported rather than asserted for exactly
/// that reason: it is a claim about the workload, and the workload cannot produce one yet.
static SGIS_ROUTED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// vINTs later drained from the pending set into a freed list register.
static SGIS_DRAINED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// Maintenance interrupts ([`gic::MAINT_INTID`]) EL2 took on this path.
static MAINT_TAKEN: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// **Deliver a vINT to the RUNNING vCPU, or record it as pending if the list-register bank is full.**
///
/// Total by construction: there is no failure to report, which is what removes the `park()` this
/// replaces. The two outcomes are "in a list register now" and "in the set until one frees".
///
/// ⚠ **Was `deliver_or_defer_sgi` until ⑱-6, and the rename is the whole of what that rung changed
/// here.** Nothing in this function was ever about SGIs — it is the running vCPU's bank, its pending
/// set, and the `UIE` discipline over both — but the name said otherwise, and ⑱-6 needed exactly
/// this behaviour for a *routed SPI*. Copying it under a second name would have given the subtlest
/// rule in the file (arm `UIE` only for the running vCPU, and only over a non-empty set) two
/// derivations to drift apart. One encoder, as with `encode_lr` (#55).
fn deliver_or_defer_vint(
    set: &crate::pending::PendingSet,
    named: &AtomicU64,
    delivered: &AtomicU64,
    deferred: &AtomicU64,
    intid: u32,
) {
    // ⑱-5: counted HERE and not at the routing loop, and the difference was found by the witness on
    // its first run. The `selftest` overflow probe calls this function directly to manufacture a full
    // bank — a disposition that no `ICC_SGI1R_EL1` decode named — so counting the pair at the decode
    // left `named` one short of `delivered + deferred` in exactly the configuration the REQUIRED gate
    // boots. Counting it where the disposition happens makes the identity hold for every caller
    // rather than for the ones this rung happened to think of.
    named.fetch_add(1, Ordering::Relaxed);
    if gic::inject(intid) {
        delivered.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if set.mark(intid) {
        deferred.fetch_add(1, Ordering::Relaxed);
        // Level-based, and armed only because something is now waiting — see
        // `gic::set_underflow_interrupt` for why arming it over an empty set livelocks EL2.
        gic::set_underflow_interrupt(true);
    }
    // `mark` refuses only an INTID the emulated distributor cannot name, and neither caller can
    // produce one: an SGI comes from a FOUR-BIT field (`hv_vdev::sgi`), so it is at most 15, and a
    // routed SPI reached here through `VirtGic::spi_route`, which answers `None` for anything
    // outside the distributor's INTID space. Written as a condition rather than an assert because a
    // panic here would be the halt coming back.
}

// ─── ⑱-6: which vCPU a routed SPI goes to ────────────────────────────────────────────────────────

/// **The SPI the ⑱-6 witness routes — and it is the guest's OWN UART interrupt, not a number
/// invented here.**
///
/// `guest.dts` gives `pl011@9000000` `interrupts = <0x00 0x01 0x04>` — SPI 1, so INTID 33 — and the
/// guest names it straight back in `/proc/interrupts`:
///
/// ```text
///  13:          0          0    GICv3  33 Level     uart-pl011
/// ```
///
/// ★ **Measured on `main` before this witness was designed** (design-lesson #186), and two
/// properties of that one line are what make it the right choice over an SPI EL2 picked for itself:
///
/// * The kernel prints **its own IRQ number and the GIC INTID side by side**, so "the interrupt the
///   guest routed" and "the interrupt EL2 delivered" are demonstrably the same object rather than
///   two numbers that happen to match.
/// * The count is **zero on both CPUs across an entire boot** — the emulated PL011 never raises —
///   so the baseline is not merely low, it is empty, and anything appearing in that row is EL2's
///   injection and can be nothing else.
const WITNESS_SPI: u32 = 33;

/// ⑱-6 — `(SPI, target vCPU)` pairs EL2 undertook to deliver. Same identity as
/// [`SGI_TARGETS_NAMED`]: `named == delivered + deferred + routed`, one disposition each.
static SPI_TARGETS_NAMED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// ⑱-6 — routed SPIs that went into the running vCPU's list registers.
static SPIS_DELIVERED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// ⑱-6 — routed SPIs that went into the running vCPU's pending set because its bank was full.
static SPIS_DEFERRED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// ⑱-6 — **SPIs marked for a vCPU that was NOT the one running.** The rung's whole point: before
/// this, an SPI went wherever the pCPU happened to be.
static SPIS_ROUTED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// ⑱-6 — SPIs whose routing named **no vCPU this guest has**: a foreign cluster, or `IRM` (1-of-N),
/// which `GICD_TYPER.No1N` tells the guest is unsupported.
///
/// ⚠ **Counted and reported, never a halt.** An undelivered interrupt is the guest's problem and
/// stays inside the guest; a `park()` here would be a halt a guest could reach by writing one
/// register, taking its peer down with it — which is exactly the defect ⑱-5 removed from the SGI
/// path and must not be reintroduced on this one.
static SPIS_UNROUTABLE: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// ★★ ⑱-7/⑱-8 — **how many times an affinity this guest named ALSO described a PEER's vCPU.** Per
/// issuing guest, counted for both routing axes (`ICC_SGI1R_EL1` in [`handle_linux_sysreg_trap`],
/// `GICD_IROUTER` in [`deliver_spi`]) by [`note_affinity_collisions`].
///
/// **A hazard, measured — not a guard that fired.** ⑱-7 counted *refusals*; ⑱-8 made the refusal
/// unnecessary by carrying confinement in a role, which would have driven a refusal counter to zero
/// and left a green witness measuring nothing. See [`note_affinity_collisions`].
///
/// Non-zero on every boot, in the hundreds, because `vcpu_affinity` **takes no guest argument** —
/// dom 1's vCPU 1 and dom 2's vCPU 1 have identical affinity, so every IPI Linux sends collides. A
/// zero would mean the guests had stopped colliding and the whole argument for the role fence would
/// need re-reading.
static AFFINITY_COLLISIONS: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// ⑱-6 — set when the guest has re-aimed [`WITNESS_SPI`] away from its boot vCPU. See
/// [`maybe_fire_spi_witness`] for why arming and firing are two moments and not one.
static SPI_WITNESS_ARMED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// ⑱-6 — whether this guest's witness injection has already been made. Fires at most once.
static SPI_WITNESS_FIRED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// **Deliver an SPI to the vCPU the GUEST routed it to.**
///
/// The ⑱-6 seam, and structurally the `ICC_SGI1R_EL1` loop in [`handle_linux_sysreg_trap`] with the
/// decode swapped: offer the route every vCPU of **this** guest and no others, and give the one it
/// names the same two dispositions the SGI path uses. The confinement argument is inherited verbatim
/// — a routing value matching a peer's affinity would still never be asked about, because the peer's
/// vCPUs are not in this iteration.
///
/// ⚠ **The `UIE` asymmetry is the subtle half, and it is why this calls
/// [`deliver_or_defer_vint`] rather than open-coding the running case.** A sibling's bank is not
/// live, so there is nothing to inject into and `UIE` must NOT be armed: arming it here would make
/// EL2 take a maintenance interrupt about a bank that is already empty (III-1's livelock, reached
/// from the other side).
fn deliver_spi(route: hv_vdev::irouter::SpiRoute, running: Running, intid: u32) {
    let slot = running.guest();
    // ⑱-8 — this guest's vCPUs as a ROLE. There is no peer in this iteration to guard against; see
    // `Running::own_vcpus`. The hazard that makes the role worth having is counted separately,
    // because with the guard gone there is nothing left whose firing could stand in for it.
    note_affinity_collisions(running, |aff| route.targets(aff));
    leak_to_peers_if_probing(running, |aff| route.targets(aff), intid);
    for own in running.own_vcpus() {
        let target = own.vcpu();
        // ⑱-6's REMOVE-THE-FIX probe: ignore the routing and take whichever vCPU is on the pCPU —
        // the behaviour that rung replaced. See `docs/VGIC-SPI-ROUTING.md` for the measured result.
        #[cfg(feature = "spi-route-probe")]
        let names_it = target == running.vcpu();
        #[cfg(not(feature = "spi-route-probe"))]
        let names_it = route.targets(vcpu_affinity(target.get()));
        if !names_it {
            continue;
        }
        if target == running.vcpu() {
            deliver_or_defer_vint(
                LINUX_PENDING.of(running),
                SPI_TARGETS_NAMED.at(slot),
                SPIS_DELIVERED.at(slot),
                SPIS_DEFERRED.at(slot),
                intid,
            );
        } else if LINUX_PENDING.own(own).mark(intid) {
            SPI_TARGETS_NAMED.at(slot).fetch_add(1, Ordering::Relaxed);
            SPIS_ROUTED.at(slot).fetch_add(1, Ordering::Relaxed);
        }
        // `spi_route` names AT MOST ONE vCPU — proven ∀-value by
        // `a_route_names_at_most_one_vcpu` — so there is nothing after the first match, and this
        // return is what makes that theorem load-bearing rather than decorative.
        return;
    }
    SPIS_UNROUTABLE.at(slot).fetch_add(1, Ordering::Relaxed);
}

/// ★★ ⑱-8 — **count how many of the OTHER guests' vCPUs the affinity a guest just named ALSO
/// describes.** The hazard, measured; not a guard that fired.
///
/// ⚠ **⑱-7 counted refusals, and ⑱-8 deleted the thing being counted.** With confinement carried by
/// [`Running::own_vcpus`](crate::role::Running::own_vcpus) there is no peer branch left to
/// increment, so a witness built on "the guard fired" would have gone silently to zero — passing,
/// while measuring nothing (design-lesson #199's shape: a gate you merely observe is not a gate,
/// and #215's: ask what a checker prints when it has nothing to check).
///
/// So the quantity changed rather than the counter being dropped. It now answers the question the
/// role fence exists to make safe: *how often does a guest name an affinity that a peer's vCPU also
/// has?* MEASURED in the hundreds per boot — because `vcpu_affinity` takes no guest argument, every
/// IPI Linux sends collides. **That number is the justification for the fence**, and it is the one
/// thing that would tell a future reader the collision is real rather than theoretical.
///
/// Looking at peers is allowed and is all this does; **delivering** to them is what the role makes
/// unrepresentable.
fn note_affinity_collisions(running: Running, names: impl Fn(u64) -> bool) {
    let slot = running.guest();
    let mut collisions = 0u64;
    for (g, v) in crate::role::census(NUM_GUESTS) {
        if g != slot && names(vcpu_affinity(v.get())) {
            collisions += 1;
        }
    }
    if collisions > 0 {
        AFFINITY_COLLISIONS
            .at(slot)
            .fetch_add(collisions, Ordering::Relaxed);
    }
}

/// ⑱-7's REMOVE-THE-FIX probe, and ⑱-8 changed what it demonstrates.
///
/// It can no longer be written as "drop a guard", because there is no guard — so it **deliberately
/// goes around the role**, reaching peers through [`PerVcpu::at`](crate::role::PerVcpu::at), the
/// arbitrary-index accessor setup and report code legitimately use.
///
/// ★ **That is the honest statement of what a type fence buys, and it is narrower than "the bug is
/// impossible".** A future author can still deliver to a peer — but only by naming a guest index
/// obtained from somewhere else, which is a visible, deliberate act in a diff, rather than the
/// silent default of an accessor that takes a `usize`. The fence is against ACCIDENT.
#[cfg(feature = "no-irq-confinement")]
fn leak_to_peers_if_probing(running: Running, names: impl Fn(u64) -> bool, intid: u32) {
    let slot = running.guest();
    for (g, v) in crate::role::census(NUM_GUESTS) {
        if g != slot && names(vcpu_affinity(v.get())) {
            let _ = LINUX_PENDING.at(g, v).mark(intid);
        }
    }
}

/// The probe's absence, in the shape the call sites can name unconditionally.
#[cfg(not(feature = "no-irq-confinement"))]
fn leak_to_peers_if_probing(_: Running, _: impl Fn(u64) -> bool, _: u32) {}

/// **Arm the ⑱-6 witness when the GUEST moves [`WITNESS_SPI`] off the vCPU it booted on.**
///
/// ★ **The trigger is the guest's own routing write, and that is what orders the witness.** Nothing
/// here tells the guest when to act and no new EL2↔guest channel exists: arm64 Linux writes the
/// whole routing table at `gic_dist_init` (the measured trace shows `0x6100..=0x68f8`, every SPI),
/// pointing every SPI at the boot CPU, and later writes one entry when something changes an IRQ's
/// affinity. So "the route names a non-boot vCPU" cannot be true before the guest has *chosen* it,
/// and the injection cannot race ahead of the decision it is meant to honour.
///
/// Arms rather than delivers — see [`maybe_fire_spi_witness`] for why the moment of the write is
/// the one moment the injection must NOT be made.
fn arm_spi_witness(running: Running, route: Option<hv_vdev::irouter::SpiRoute>) {
    let Some(route) = route else {
        return;
    };
    // Still on the boot vCPU — the guest has not made a routing decision worth witnessing yet. NOT
    // `route.targets(some non-boot vCPU)`: a foreign cluster or an `IRM` write names no vCPU at all,
    // and the rung wants those armed too, so `SPIS_UNROUTABLE` is exercised rather than reasoned
    // about.
    if route.targets(vcpu_affinity(crate::role::VcpuIdx::boot().get())) {
        return;
    }
    SPI_WITNESS_ARMED
        .at(running.guest())
        .store(1, Ordering::Relaxed);
}

/// **Fire the armed ⑱-6 witness — and ONLY from a vCPU that is not the one the guest named.**
///
/// ★★ **That condition is the entire witness, and the first version of this rung did not have it.**
///
/// ⚠ **MEASURED, and it is design-lesson #198 walked straight into.** The injection was originally
/// made at the routing write itself. The gate went green and the guest's own `/proc/interrupts`
/// said `cpu0=0 cpu1=1` — the interrupt had landed on CPU1, exactly as asked. **It proved nothing.**
/// The `smp_affinity` write is executed by whatever CPU is running PID 1, which was *CPU1*, so the
/// vCPU the guest routed to and the vCPU that happened to be on the pCPU were the same one — and
/// EL2 reported `1 delivered, 0 routed`, i.e. it had taken the running-vCPU path. **An
/// implementation that ignored `GICD_IROUTER` entirely would have produced an identical log.** The
/// discriminator was a property of the fixture, not of the fix.
///
/// So the injection is deferred to a moment where the two answers *differ*: armed at the write,
/// fired from a `WFI` trap taken on a **different** vCPU. Then the sibling path is the only one that
/// can run, "delivered to the running vCPU" becomes structurally impossible, and the verdict can
/// assert `routed == 1 && delivered == 0` rather than merely counting.
///
/// The `WFI` path is the right place for the second half: the guest's one-second idle window
/// (`guest-init.sh`) produces hundreds of these on **both** vCPUs, so a moment satisfying the
/// condition is reached reliably rather than hoped for.
///
/// Gated on [`is_enabled`](crate::vgic::DeployedGic::is_enabled) as well, so the witness goes
/// through **both** halves of the mediation seam rather than around one: EL2 forwards this interrupt
/// only because the guest asked for it, and to the vCPU the guest named.
fn maybe_fire_spi_witness(running: Running) {
    let slot = running.guest();
    if SPI_WITNESS_ARMED.at(slot).load(Ordering::Relaxed) == 0
        || SPI_WITNESS_FIRED.at(slot).load(Ordering::Relaxed) != 0
    {
        return;
    }
    // `try_` because this runs on an interrupt-adjacent path: a contended borrow means try again on
    // the next `WFI`, of which there are hundreds — never a halt.
    let Some(mut dev) = VGIC.try_borrow_mut() else {
        return;
    };
    let route = dev.at_mut(slot).spi_route(WITNESS_SPI);
    let enabled = dev.at_mut(slot).is_enabled(running.vcpu(), WITNESS_SPI);
    drop(dev);

    let Some(route) = route else {
        return;
    };
    if !enabled {
        return;
    }
    // ★ THE DISCRIMINATOR. Deliver only from a vCPU the route does NOT name, so that honouring the
    // routing and ignoring it lead to different vCPUs — and the guest's own per-CPU interrupt
    // counts can tell which happened.
    if route.targets(vcpu_affinity(running.vcpu().get())) {
        return;
    }
    if SPI_WITNESS_FIRED.at(slot).swap(1, Ordering::Relaxed) != 0 {
        return;
    }
    deliver_spi(route, running, WITNESS_SPI);
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
/// Takes the SET and the counter, not a slot — so **which guest** is decided at the call site by a
/// role-typed accessor ([`crate::role`]) and cannot be got wrong here. Passing the outgoing guest's
/// set at a switch was one of the two MEASURED silent swaps this rung closes.
fn flush_pending_to_lrs(set: &crate::pending::PendingSet, drained: &AtomicU64) -> usize {
    let n = gic::num_list_registers();
    let mut placed = 0;
    for i in 0..n {
        if !gic::lr_is_free(gic::read_lr(i)) {
            continue;
        }
        match set.take_next() {
            Some(intid) => {
                // Back through the raw allocator rather than writing the list register here, so the
                // set and the synchronous path place interrupts through exactly one encoder (#55).
                if gic::inject(intid) {
                    placed += 1;
                    drained.fetch_add(1, Ordering::Relaxed);
                } else {
                    // Cannot happen single-CPU with a free LR just observed — but do not lose the
                    // vINT on a surprise.
                    let _ = set.mark(intid);
                    break;
                }
            }
            None => break,
        }
    }
    gic::set_underflow_interrupt(!set.is_empty());
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
/// one's `poison`: the bank has already been captured into `VCPU_CTX.out_mut(cur)`, and every list register
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
fn probe_lr_overflow(g: Outgoing) {
    let n = gic::num_list_registers();
    for i in 0..n {
        gic::write_lr(i, 0);
    }
    let started_empty = LINUX_PENDING.out(g).is_empty();

    let mut filled = 0;
    for k in 0..n {
        if gic::inject(PROBE_FILL_BASE + k as u32) {
            filled += 1;
        }
    }
    let bank_refuses = !gic::inject(PROBE_FILL_BASE + n as u32);

    deliver_or_defer_vint(
        LINUX_PENDING.out(g),
        SGI_TARGETS_NAMED.out(g),
        SGIS_DELIVERED.out(g),
        SGIS_DEFERRED.out(g),
        PROBE_OVERFLOW_INTID,
    );
    let deferred = !LINUX_PENDING.out(g).is_empty();
    let armed = gic::underflow_interrupt_armed();

    gic::write_lr(0, 0);
    let placed = flush_pending_to_lrs(LINUX_PENDING.out(g), SGIS_DRAINED.out(g));
    let drained = LINUX_PENDING.out(g).is_empty();
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
        let deferred = SGIS_DEFERRED.at(slot).load(Ordering::Relaxed);
        let drained = SGIS_DRAINED.at(slot).load(Ordering::Relaxed);
        let maint = MAINT_TAKEN.at(slot).load(Ordering::Relaxed);
        let _ = writeln!(
            uart,
            "baleen: pending dom {}: {deferred} vINT(s) deferred when the list-register bank was \
             full, {drained} drained back into it, {maint} maintenance interrupt(s) taken (all zero \
             on a boot whose guest takes its own interrupts — this is a diagnostic, not a claim)",
            slot_dom(slot)
        );
    }
}

/// ★ **⑱-5's witness: every SGI target the decode NAMED got exactly one disposition.**
///
/// ## The identity, and why it is the mechanism rather than the workload
///
/// One `ICC_SGI1R_EL1` write can name several vCPUs — a broadcast names every one but the sender —
/// so the quantity to conserve is `(SGI, target vCPU)` PAIRS, not writes. Each takes exactly one of
/// three exits:
///
/// * **delivered** — the target is the running vCPU and a list register was free;
/// * **deferred** — the target is the running vCPU and its bank was full, so its own set holds it;
/// * **routed** — the target is a *sibling*, whose bank is not live, so the set is the whole
///   delivery and `UIE` is deliberately not armed.
///
/// (The `selftest` overflow probe reaches the first two directly, without a decode — see
/// [`SGI_TARGETS_NAMED`], where counting them cost this witness a red run to learn.)
///
/// There is no fourth exit, and none of the three can be skipped: `PendingSet::mark` refuses only an
/// INTID outside the distributor's space, and ⑱-5's Kani harness
/// `an_sgi_intid_is_always_in_the_sgi_range` proves an SGI id is always 0..15. **That premise used to
/// be prose** — `pending.rs` argued it from "a guest SGI comes from a four-bit field" — and is now a
/// theorem, which is the quiet half of moving the decode under the fence.
///
/// So `named == delivered + deferred + routed` holds on every boot whatever the guests do, and it is
/// **false on `main`**, where nothing counts targets because nothing decodes them.
///
/// ## What is reported and NOT asserted, and why that restraint is the whole discipline
///
/// **`routed` reads ZERO today, and asserting anything about it would be this arc's standing
/// mistake.** ⑱-5 lands before ⑱-4 deliberately (#163, the ⑱-2 pattern: prove at N, deploy at 1), so
/// no sibling vCPU is `Runnable` and no guest can name one. A count of zero here is a correct boot,
/// and a positive count becomes the point of the rung that starts a second vCPU — not of this one.
///
/// ## Honest ceiling
///
/// This says every named target was disposed of. It does **not** say the decode named the RIGHT
/// targets — that claim is the five Kani harnesses over `hv_vdev::sgi`, which quantify over the
/// whole 64-bit value a guest can write, and their four kill probes. A boot witness cannot make it,
/// because the shipped Alpine kernel with one runnable vCPU only ever names itself.
fn report_sgi_routing(uart: &mut Pl011) {
    for slot in 0..NUM_GUESTS {
        if !witnesses_assertable(slot) {
            continue;
        }
        let dom = slot_dom(slot);
        let named = SGI_TARGETS_NAMED.at(slot).load(Ordering::Relaxed);
        let delivered = SGIS_DELIVERED.at(slot).load(Ordering::Relaxed);
        let deferred = SGIS_DEFERRED.at(slot).load(Ordering::Relaxed);
        let routed = SGIS_ROUTED.at(slot).load(Ordering::Relaxed);
        if named == delivered + deferred + routed {
            let _ = writeln!(
                uart,
                "baleen: sgiroute OK: dom {dom}'s SGIs are decoded under the fence and ROUTED BY \
                 TARGET — {named} (write, target) pair(s) named by ICC_SGI1R_EL1, each disposed of \
                 exactly once: {delivered} into the running vCPU's list registers, {deferred} \
                 deferred to its own pending set, {routed} routed to a SIBLING vCPU's set (zero \
                 until a second vCPU is startable, which is ⑱-4 — reported, not asserted)"
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: sgiroute FAIL: dom {dom} undertook {named} SGI deliveries but disposed of \
                 {delivered} + {deferred} + {routed} — a target reached no vCPU at all, or was \
                 counted twice. An IPI a guest sent has gone missing"
            );
            crate::park();
        }
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
    //
    // ⑱-3b-i: the whole ROLE, not just its guest. That sentence above is about a **vCPU** context —
    // and two of the decisions below are about state the GICv3 banks per vCPU (the timer PPI's
    // enable, the pending set), which this handler used to take from `BOOT_VCPU`. `slot` stays
    // beside it for the genuinely per-guest state (the console, the domain id).
    let running = current_vcpu();
    let slot = running.guest();

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
        preempt_through_the_scheduler(running, unsafe { &mut *frame });
        return;
    }

    if intid == gic::VTIMER_INTID {
        // ③-b1 — THE MEDIATION SEAM. Before this rung EL2 forwarded the timer unconditionally, which
        // was correct with one guest and is exactly the decision that has to become per-guest for
        // two. Now the interrupt is delivered only if the guest asked for it **in its own emulated
        // distributor**, which lives in EL2 memory the guest cannot reach. A guest that has not
        // enabled INTID 27 does not get INTID 27 — and, come ③-b, cannot enable anyone else's.
        if !VGIC
            .borrow_mut()
            .at_mut(slot)
            .is_enabled(running.vcpu(), intid)
        {
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
        // **The discriminating probe, once per boot.** The shipped guest takes all 59 of its SGIs,
        // so its bank never fills and `TIMER_DEFERRED` would read ZERO on a good boot — a counter
        // that proves nothing, which is the "WFI traps > 0" mistake this project already made once.
        // So the condition is MANUFACTURED: fill the bank right before the forward and let the REAL
        // deferral path run.
        //
        // **Filled with ACTIVE list registers, and the first attempt at this HUNG THE GUEST.** The
        // obvious fill is a few SGIs the guest has enabled — and on arm64 Linux **SGI 2 is
        // `IPI_CPU_STOP`**, so the probe told the kernel to halt itself and the boot died just after
        // reaching userspace. An Active entry occupies the slot (`lr_is_free` refuses it, so the
        // injector skips it) while never being PRESENTED, because only a *Pending* entry is offered
        // to the guest's CPU interface. The guest is therefore handed nothing at all.
        //
        // ⚠ **The fill MUST be undone before returning, and assuming otherwise cost a hung boot.**
        // The first version left the entries in place, reasoning that the next switch poisons the
        // bank and restores the incoming vCPU's own. True, and irrelevant — the switch **SAVES
        // first**: `ctx.out_mut(cur).save()` captured the filler entries into that vCPU's context, so they
        // were faithfully restored on its every switch-in from then on. Its bank was permanently
        // full, it never got another tick, and dom 2 stalled while dom 1 powered off normally. The
        // bank is therefore snapshotted here and put back below.
        #[cfg(feature = "selftest")]
        let mut probe_fill: Option<[u64; gic::MAX_LIST_REGISTERS]> = None;
        #[cfg(feature = "selftest")]
        if !TICK_DEFER_PROBED.swap(true, Ordering::Relaxed) {
            let mut saved = [0u64; gic::MAX_LIST_REGISTERS];
            for (k, slot) in saved.iter_mut().enumerate().take(gic::num_list_registers()) {
                *slot = gic::read_lr(k);
                gic::write_lr(
                    k,
                    hv_vdev::vgic_cpuif::encode_active(TICK_PROBE_FILL_INTID + k as u32),
                );
            }
            probe_fill = Some(saved);
        }
        if !gic::inject_hw(gic::VTIMER_INTID, gic::VTIMER_INTID) {
            // ★ **DEFER, and the tick is not lost.** This used to `park()` — the last halt a guest
            //   could reach, and it could reach it with four instructions (see [`TIMER_DEFERRED`]).
            //
            //   **Nothing new is needed to redeliver it, which is why there is no flag here.** The
            //   interrupt is left **Active** with only a priority drop below, exactly as the success
            //   path leaves it, so it cannot re-signal and storm EL2. At the next switch —
            //   guaranteed within one `CNTHP` slice, because EL2 owns that clock and the guest
            //   cannot mask it — `gic::release_forwarded_timer` deactivates it, and the guest's own
            //   `CNTV_CVAL_EL0` is *still expired*, so the level re-asserts and the tick arrives
            //   again through this same path. A level-triggered source that nobody has serviced does
            //   not need remembering; it needs only to stop being Active.
            //
            //   So the guest is late by at most one scheduling round, and only the guest that filled
            //   its own bank is affected.
            // Put the guest's own bank back before leaving. The deferral is REAL either way:
            // `inject_hw` genuinely failed against a genuinely full bank.
            #[cfg(feature = "selftest")]
            if let Some(saved) = probe_fill {
                for (k, &lr) in saved.iter().enumerate().take(gic::num_list_registers()) {
                    gic::write_lr(k, lr);
                }
            }
            TIMER_DEFERRED.at(slot).fetch_add(1, Ordering::Relaxed);
            gic::eoi_physical(intid);
            return;
        }
        TIMER_FORWARDED.at(slot).fetch_add(1, Ordering::Relaxed);
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
        MAINT_TAKEN.at(slot).fetch_add(1, Ordering::Relaxed);
        // Drain FIRST: the interrupt is level-based on `UIE` + bank occupancy, and the drain is what
        // clears `UIE` when nothing is left. Deactivating before that could re-assert immediately.
        //
        // ⑱-3b-i: **the RUNNING vCPU's set**, and this is the site where the constant was worst.
        // The signal is "the list-register bank is running dry", and the bank is the hardware's —
        // i.e. the running vCPU's. Draining `BOOT_VCPU`'s set here would put vCPU 0's deferred vINTs
        // into vCPU 1's live list registers (an interrupt delivered to the wrong vCPU of the same
        // guest, which is III-1's leak reopened inside a guest), *and* leave vCPU 1's own set
        // undrained with `UIE` level-asserted over it — EL2 re-entering on a maintenance interrupt
        // that its own drain can never clear.
        let _ = flush_pending_to_lrs(LINUX_PENDING.of(running), SGIS_DRAINED.at(slot));
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

// ── ⑲-3b — a transfer in flight ACROSS guest execution ──────────────────────────────────────────
//
// ⚠ **THE HONEST CLAIM, and it is narrower than the words "simultaneous DMA" suggest.** One pCPU,
// TCG, and an `edu` engine that completes on a virtual-clock timer *between* translation blocks: at
// the instant the copy happens, no guest instruction is mid-execution. What is true, and what
// honest-ledger item 2(b) actually asks for, is that **the transfer was in flight across an interval
// in which guest instructions executed** — the machine was NOT quiesced around the device, which is
// the caveat every DMA result before this one carried. Say "in flight across guest execution", never
// "concurrent with it".
//
// The state machine below lives on the exit path because that is the only place EL2 exists while a
// guest runs. It is deliberately branch-light: one relaxed load rejects it in the steady state.

/// Entries to EL2 before the first transfer is kicked. Non-zero on purpose — the guests must already
/// be running when the device is pointed at them, so the rung is not "a device aimed at a machine
/// that then started" but "a device aimed at a machine that was already going".
#[cfg(feature = "smmu")]
const FLIGHT_KICK_AFTER: u64 = 200;

/// The floor each arm's progress must clear. Measured headroom is ~68,000 exits per flight, so this
/// is four orders of magnitude clear of the real number — it is a non-vacuity floor, not a claim
/// about the workload.
#[cfg(feature = "smmu")]
const FLIGHT_EXIT_FLOOR: u64 = 100;

/// How often the exit path may spend an MMIO read asking whether the engine retired. Every entry
/// would be an exit to QEMU per exit to EL2; the resolution this costs is ±64 against ~68,000.
#[cfg(feature = "smmu")]
const FLIGHT_RETIRE_POLL: u64 = 64;

#[cfg(feature = "smmu")]
mod flight {
    use super::{AtomicU64, PerGuest, NUM_GUESTS};
    /// 0 not armed · 1 armed, waiting · 2 permitted arm in flight · 3 refused arm in flight · 5 done.
    pub(super) static PHASE: AtomicU64 = AtomicU64::new(0);
    pub(super) static EXITS: AtomicU64 = AtomicU64::new(0);
    pub(super) static KICK1: AtomicU64 = AtomicU64::new(0);
    pub(super) static LAND1: AtomicU64 = AtomicU64::new(0);
    pub(super) static KICK2: AtomicU64 = AtomicU64::new(0);
    pub(super) static RETIRE2: AtomicU64 = AtomicU64::new(0);
    /// Whether the permitted target had ALREADY changed when the transfer was kicked. Must be 0, or
    /// "it landed" says nothing.
    pub(super) static LANDED_AT_KICK: AtomicU64 = AtomicU64::new(0);
    pub(super) static PEER_INTACT: AtomicU64 = AtomicU64::new(0);
    pub(super) static EV_KIND: AtomicU64 = AtomicU64::new(0xff);
    pub(super) static EV_SID: AtomicU64 = AtomicU64::new(0);
    pub(super) static EV_ADDR: AtomicU64 = AtomicU64::new(0);
    /// Per-guest exits taken while each arm was in flight — the plural form of "a vCPU ran".
    pub(super) static EXITS_PERMITTED: PerGuest<AtomicU64, NUM_GUESTS> =
        PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);
    pub(super) static EXITS_REFUSED: PerGuest<AtomicU64, NUM_GUESTS> =
        PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);
    /// How often the exiting guest's `ELR_EL2` differed from the previous exit's — the PC moved, so
    /// instructions ran. A count of exits alone would also be produced by a guest taking the same
    /// trap forever.
    pub(super) static ELR_MOVES_PERMITTED: AtomicU64 = AtomicU64::new(0);
    pub(super) static ELR_MOVES_REFUSED: AtomicU64 = AtomicU64::new(0);
    pub(super) static LAST_ELR: AtomicU64 = AtomicU64::new(0);
    // The handle, flattened so the exit path needs no borrow.
    pub(super) static BAR0: AtomicU64 = AtomicU64::new(0);
    pub(super) static SID: AtomicU64 = AtomicU64::new(0);
    pub(super) static OWN_IPA: AtomicU64 = AtomicU64::new(0);
    pub(super) static OWN_PA: AtomicU64 = AtomicU64::new(0);
    pub(super) static PEER_IPA: AtomicU64 = AtomicU64::new(0);
    pub(super) static PEER_PA: AtomicU64 = AtomicU64::new(0);
}

#[cfg(feature = "smmu")]
fn flight_handle() -> crate::dmawitness::InFlight {
    crate::dmawitness::InFlight {
        bar0: flight::BAR0.load(Ordering::Relaxed),
        sid: flight::SID.load(Ordering::Relaxed) as u32,
        own_ipa: flight::OWN_IPA.load(Ordering::Relaxed),
        own_pa: flight::OWN_PA.load(Ordering::Relaxed),
        peer_ipa: flight::PEER_IPA.load(Ordering::Relaxed),
        peer_pa: flight::PEER_PA.load(Ordering::Relaxed),
    }
}

/// Record that THIS guest executed: one exit charged to its slot, and whether the PC moved.
#[cfg(feature = "smmu")]
fn flight_note_progress(per_guest: &PerGuest<AtomicU64, NUM_GUESTS>, moves: &AtomicU64) {
    per_guest.at(current_slot()).fetch_add(1, Ordering::Relaxed);
    let elr: u64;
    // SAFETY: `ELR_EL2` is readable at EL2 and holds the address the exiting guest will resume at.
    unsafe {
        asm!("mrs {e}, ELR_EL2", e = out(reg) elr, options(nomem, nostack, preserves_flags));
    }
    if flight::LAST_ELR.swap(elr, Ordering::Relaxed) != elr {
        moves.fetch_add(1, Ordering::Relaxed);
    }
}

/// **⑲-3b's exit-path step.** Runs on every entry to EL2 from a guest.
#[cfg(feature = "smmu")]
fn flight_tick() {
    let n = flight::EXITS.fetch_add(1, Ordering::Relaxed) + 1;
    let phase = flight::PHASE.load(Ordering::Relaxed);
    if phase == 0 || phase >= 5 {
        return;
    }
    let f = flight_handle();
    match phase {
        // Armed, but let the guests get going first.
        1 => {
            if n >= FLIGHT_KICK_AFTER {
                crate::dmawitness::inflight_kick(&f, true);
                // Non-vacuity, read AFTER the kick and before any guest runs again: the target must
                // still hold its sentinel, i.e. the transfer has not already happened.
                if crate::dmawitness::inflight_landed(&f) {
                    flight::LANDED_AT_KICK.store(1, Ordering::Relaxed);
                }
                flight::KICK1.store(n, Ordering::Relaxed);
                flight::PHASE.store(2, Ordering::Relaxed);
            }
        }
        // The permitted arm is in flight. `inflight_landed` is a plain read, so this is affordable
        // on every entry and the landing is caught within one exit of happening.
        2 => {
            flight_note_progress(&flight::EXITS_PERMITTED, &flight::ELR_MOVES_PERMITTED);
            if crate::dmawitness::inflight_landed(&f) {
                flight::LAND1.store(n, Ordering::Relaxed);
                // Straight into the refusal arm: same device, same derived binding, an IPA in the
                // PEER's window. This re-seeds both sites, which is why LAND1 is recorded first.
                crate::dmawitness::inflight_kick(&f, false);
                flight::KICK2.store(n, Ordering::Relaxed);
                flight::PHASE.store(3, Ordering::Relaxed);
            }
        }
        // The refused arm is in flight. Nothing will land, so retirement is the only signal and it
        // costs an MMIO read — polled sparsely.
        3 => {
            flight_note_progress(&flight::EXITS_REFUSED, &flight::ELR_MOVES_REFUSED);
            if n.is_multiple_of(FLIGHT_RETIRE_POLL) && crate::dmawitness::inflight_retired(&f) {
                flight::RETIRE2.store(n, Ordering::Relaxed);
                flight::PEER_INTACT.store(
                    u64::from(crate::dmawitness::inflight_peer_intact(&f)),
                    Ordering::Relaxed,
                );
                if let Some((kind, sid, addr)) = crate::dmawitness::inflight_event() {
                    flight::EV_KIND.store(u64::from(kind), Ordering::Relaxed);
                    flight::EV_SID.store(u64::from(sid), Ordering::Relaxed);
                    flight::EV_ADDR.store(addr, Ordering::Relaxed);
                }
                flight::PHASE.store(5, Ordering::Relaxed);
            }
        }
        _ => {}
    }
}

/// Record that EL2 has just been entered from a guest, and charge the interval to whoever held the
/// pCPU (③-b2b-ii-e). Called first thing in both Linux-mode handlers, which between them are every
/// entry to EL2 on this path.
///
/// ⑲-3b hangs its exit-path step here for exactly that reason: this is every entry to EL2, so it is
/// the one place that can observe a transfer while a guest is the thing running.
fn note_el2_entry() {
    #[cfg(feature = "smmu")]
    flight_tick();
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
/// **One per guest since ③-b2b-ii-a, and one per vCPU since ⑱-3a**, because a context is what a
/// switch moves: with one slot, a switch-to-self resumes the same registers it saved, and the array
/// is what makes "resume the OTHER one" expressible at all. The vCPU axis is not a generalisation
/// for its own sake — `VcpuCtx` declares only `PerVcpuState`, so putting it back on a single axis
/// does not compile.
static VCPU_CTX: BootCell<PerVcpu<vcpu::VcpuCtx, NUM_GUESTS, VCPUS_PER_GUEST>> = BootCell::new(
    "LINUX_VCPU_CTX",
    PerVcpu::new([const { [VCPU_CTX_EMPTY; VCPUS_PER_GUEST] }; NUM_GUESTS]),
);

/// An empty context. Named because an array repeat expression needs a constant operand.
const VCPU_CTX_EMPTY: vcpu::VcpuCtx = vcpu::VcpuCtx::new();

/// How many times each guest's vCPU has been switched out and back through hv-core's scheduler.
static SWITCHES: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// ⑱-3b-ii — **dispatches of a vCPU that is not the one its guest boots on. MUST be zero.**
///
/// Not a tally: an assertion about this rung's boundary. `VCPUS_PER_GUEST` is 2, so a second vCPU
/// exists and is offered to the scheduler on every rotation — but it has no seeded context, and
/// dispatching it would `eret` to PC = 0. Nothing in this file forbids that; what refuses it is the
/// model's own `RunState`, and this counter is how EL2 says so out loud rather than trusting it.
///
/// ⚠ **A zero is only meaningful because the rotation demonstrably RAN**, which is a separate fact
/// and is `report_el2_slice`'s: EL2 owns its own clock and takes a slice expiry roughly every
/// quantum, each of which calls [`next_runnable`]. Without that, "no non-boot vCPU was dispatched"
/// would be satisfiable by never scheduling anything at all — the shape of vacuity design-lesson
/// #105 names.
///
/// ✅ **⑱-4b-ii RETIRED THAT ASSERTION, as this doc said it should.** `PSCI CPU_ON` seeds and admits
/// a second vCPU, so a non-zero count is now the point rather than a defect — **measured in the low
/// hundreds per boot (344 and 378 on two runs).** It is a WORKLOAD number and varies run to run,
/// which is why it is reported and never asserted. The counter survives as a REPORTED number; what replaced the assertion is
/// `seeded == admitted` per guest, in [`report_vcpu_census`]. Retired, not relaxed: the statement it
/// was standing in for ("no vCPU runs without a context") is still asserted, and is still true.
static DISPATCHED_NONBOOT: AtomicU64 = AtomicU64::new(0);

/// ⑱-4b-ii — **which vCPUs EL2 has established a context for.**
///
/// A vCPU with no seeded context holds a zeroed [`vcpu::VcpuCtx`]; entering it `eret`s to PC = 0,
/// which ⑱-3b-ii measured directly (`EC=0x20 ELR=FAR=0x0` on both guests, then a boot that never
/// finished).
///
/// ★ **THIS GENERALISES ⑱-3b-ii'S ASSERTION RATHER THAN RETIRING IT.** That rung asserted
/// `DISPATCHED_NONBOOT == 0` — *no vCPU but the boot one ever reached the pCPU* — which was right
/// while nothing could start one and is **false by design** here. What it was really protecting
/// against was never "a non-boot vCPU" but **an unseeded one**, and that statement stays true for
/// every rung after this: [`cpu_on`] seeds before it admits, and [`switch_context`] refuses to enter
/// a vCPU this set does not name.
///
/// Written at the three — and only three — places a vCPU acquires a context: guest A's boot `eret`,
/// the boot-time seeding of every other guest's first vCPU, and `CPU_ON`.
static VCPU_SEEDED: PerVcpu<AtomicU64, NUM_GUESTS, VCPUS_PER_GUEST> =
    PerVcpu::new([const { [const { AtomicU64::new(0) }; VCPUS_PER_GUEST] }; NUM_GUESTS]);

/// ⑱-4b-ii — secondaries `CPU_ON` seeded a context for, and secondaries it admitted to the model.
///
/// **The witness is that they are EQUAL**, and they are counted at the two sites separately rather
/// than one being inferred from the other, so a path that admitted without seeding shows up as a
/// difference instead of being invisible.
static SECONDARIES_SEEDED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);
static SECONDARIES_ADMITTED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// ⑱-4b-ii — `CPU_ON` requests EL2 REFUSED, by no particular reason (the console line says which).
///
/// Reported, never asserted: every one of these is a claim about what a guest asked for. **MEASURED
/// on the shipped boot: zero** — Linux calls `CPU_ON` exactly once per guest, with a target it owns
/// and an entry point in its own RAM, and never retries.
static CPU_ON_REFUSED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// The `SCTLR_EL1` a guest's first vCPU was entered with — **MMU off**, read off the live CPU right
/// after `init_guest_el1` cleared the enables.
///
/// ⑱-4b-ii needs it because a secondary must start in the state the primary did, and by the time a
/// guest issues `CPU_ON` the live `SCTLR_EL1` is the *primary's*, with its MMU long since on.
/// Entering a secondary with that would translate its entry point through page tables it has not
/// built. Captured once, at the one moment the value is the boot value.
static SCTLR_AT_BOOT: AtomicU64 = AtomicU64::new(0);

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
static HW_RELEASED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// How many times the **interrupt controller agreed** that the forwarded timer went Active →
/// Inactive at a switch (③-b2b-ii-c1).
///
/// **The other half of the handoff, and the half [`HW_RELEASED`] structurally cannot see.** Demoting
/// a list register is EL2 editing bytes it saved itself: delete the physical deactivate entirely and
/// that count is unchanged, the boot stays green, and guest B hangs a rung later. This one is read
/// back from `GICR_ISACTIVER0` — the GIC's own view, and the Active state is precisely what would
/// stop a second guest being signalled the tick.
static TIMER_DEACTIVATED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// How many times each guest has been switched **out** (③-b2b-ii-c2).
///
/// Distinct from [`SWITCHES`], which counts switch-*ins*, and the distinction only exists once there
/// are two runners: with A↔B alternating, a guest is switched out and back in almost but not exactly
/// the same number of times, and the timer handoff is an outgoing-side event. Comparing the two
/// would have been comparing different quantities — which is what the first version of
/// [`report_timer_handoff`] did, and it read `63 across 64 switches`.
static HANDOVERS: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

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
static FP_FOREIGN: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

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
/// ★ **⑱-4a — switch-ins at which the virtual ACTIVE PRIORITIES on the interface were not the
/// incoming vCPU's** (`ICH_AP0R<n>_EL2`/`ICH_AP1R<n>_EL2`).
///
/// The [`FP_FOREIGN`] of this rung, and **reported, never asserted**, for the same reason: it is a
/// claim about the workload — whether a switch happens to land between a vCPU's `ICC_IAR1_EL1` and
/// its EOI.
///
/// ⚠ **MEASURED on the shipped two-guest boot, and the number is why it can never be a gate: it is
/// 0, 0, 1, 1 per guest across four consecutive local boots** (~62 switch-ins each). The leak
/// really does happen on the configuration this rung lands on — so the rung is not speculative —
/// but *whether* it happens on any given boot is scheduling luck. Asserting a positive count would
/// redden half the runs; asserting zero would redden exactly when the rung starts earning its keep.
/// Design-lesson #127, for the seventh time in this arc.
///
/// ⚠ **A weaker version of this question answers ZERO, and the difference matters more than the
/// number.** The scoping probe first asked *"is the live bank non-zero at a switch?"* and measured
/// **0 of 125** — from which the leak looks absent. It is the wrong question: the bank being zero
/// is fine when the *incoming* vCPU's saved bank is also zero, and the fault is a MISMATCH, not a
/// non-zero. Comparing against the incoming context is what makes the count real.
///
/// ★ **What made it fatal, and it is why this rung exists.** With a guest's SECOND vCPU running
/// (⑱-4b's `PSCI CPU_ON`) the switch points start correlating with interrupt handling — an idle
/// Linux CPU executes `wfi` immediately after taking its tick, and `HCR_EL2.TWI` turns that into a
/// switch. `ICH_AP1R0_EL2` was then measured **stuck at `0x10000`** — bit 16, priority `0x80`,
/// which is every interrupt this port injects — inherited by the sibling vCPU, whose interface then
/// refused to signal anything at or below that priority. Both siblings wedged: the guest was
/// offered its tick forever (`TIMER_DEFERRED` 3887, four Pending vINTID 27 filling the bank) and
/// could never acknowledge one.
///
/// ⚠ **Do not read the stalled boot's switch count as the cost of a second vCPU.** That boot shows
/// ~2000 switch-ins per vCPU, but the stall is what produces them: two wedged siblings handing an
/// idle pCPU back and forth. **With this rung in place the same two-vCPU configuration settles at
/// 143 and 158** — a little above the one-vCPU boot's ~125, which is what a second tenant should
/// cost. Quoting 2000 as the healthy figure would be reading a symptom as a property.
static AP_FOREIGN: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// ★ **⑱-4a — switch-ins after which the interface's active priorities were READ BACK equal to the
/// incoming vCPU's saved ones.** The assertable half, in [`FP_RESTORE_VERIFIED`]'s shape.
///
/// Structural rather than a claim about the workload: every switch-in verifies, so this equals
/// [`SWITCHES`] on every boot regardless of what any guest does, and no arrangement of guest
/// behaviour can satisfy it by luck (design-lesson #127). It is also the conjunct that cannot be
/// satisfied by writing the registers and hoping — it asks the machine what it holds.
static AP_RESTORE_VERIFIED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

static FP_RESTORE_VERIFIED: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// How many times each guest has touched a PEER's memory and been refused by the hardware
/// (③-b2b-ii-d).
static PEER_FAULTS: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

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
static VTTBR: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

/// **⑱-4b-i — return every `Blocked` vCPU to `Runnable`.** Called from EL2's own slice expiry, and
/// once more before EL2 concludes the machine is finished.
///
/// ## Why this exists, and the residual it openly stands in for
///
/// [`handle_linux_wfi`] makes an idle vCPU `Blocked`, which is what stops the ping-pong. Something
/// then has to make it a candidate again, and the architecturally right answer is *the interrupt it
/// is waiting for* — for an idle Linux CPU, almost always its own arch-timer deadline.
///
/// ⚠ **EL2 cannot do that today, and this function is the honest substitute rather than the answer.**
/// There is one physical timer for the guests (`CNTV`, forwarded to whoever holds the pCPU) and one
/// for EL2 (`CNTHP`, its slice). A *blocked* vCPU's deadline sits in its saved `CNTV_CVAL_EL0` and
/// nothing compares it against the clock, because nothing is running it. Waking a vCPU on its own
/// deadline means EL2 keeping every vCPU's deadline and programming the earliest — a per-vCPU timer
/// subsystem, which is honest-ledger item 9's deeper form and is not this rung.
///
/// So EL2 wakes **everything, every slice**. Stated plainly, that is:
///
/// * **sound** — `WFI` is architecturally permitted to wake spuriously, so a vCPU woken early simply
///   re-executes it and blocks again. Nothing observes the difference except the counters;
/// * **bounded** — idle latency becomes at most one [`EL2_SLICE_HZ`] period rather than unbounded;
/// * **and still an enormous improvement on what it replaces** — a wake per slice per idle vCPU
///   (~100/s) against the **8,735 yields per guest per second** measured on `main`.
///
/// **What it costs:** an idle guest is woken ~100 times a second to discover it is still idle. That
/// is power and efficiency on real hardware, not correctness, and it is the price of not having
/// per-vCPU timers. It is a declared residue, not a hidden one.
fn wake_blocked_vcpus(hv: &mut Hypervisor) {
    WAKE_SWEEPS.fetch_add(1, Ordering::Relaxed);
    for (slot, v) in crate::role::census(NUM_GUESTS) {
        if hv.sched().state_of(slot_dom(slot), v.model()) != Some(RunState::Blocked) {
            continue;
        }
        sched_on(
            hv,
            slot_dom(slot),
            HvCall::SchedWake { vcpu: v.model() },
            "wake a blocked vcpu",
        );
        VCPUS_WOKEN.at(slot, v).fetch_add(1, Ordering::Relaxed);
    }
}

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
///
/// ⑱-3b-ii: takes the whole [`Running`] rather than a guest slot. The outgoing side of a switch is
/// *whichever vCPU was running*, which is a fact only the role holds — see [`Running::now_leaving`].
fn preempt_through_the_scheduler(cur: Running, frame: &mut LinuxFrame) {
    let dom = slot_dom(cur.guest());

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
    // ⑱-4b-i: the denominator for [`WAKE_SWEEPS`]. Deliberately NOT on the sweep's call line below.
    PREEMPTS.fetch_add(1, Ordering::Relaxed);
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
            vcpu: cur.vcpu().model(),
            now,
        },
        "preempt the running vcpu",
    );

    // ⑱-4b-i — EL2's slice is the clock a blocked vCPU is woken by, because EL2 has no other. See
    // [`wake_blocked_vcpus`]: this is the substitute for per-vCPU deadlines, and it is what makes
    // `Blocked` a state a vCPU comes back from rather than one it disappears into.
    // ⑱-4b-i — EL2's slice is the clock a blocked vCPU is woken by, because EL2 has no other. See
    // [`wake_blocked_vcpus`]: this is the substitute for per-vCPU deadlines, and it is what makes
    // `Blocked` a state a vCPU comes back from rather than one it disappears into.
    //
    // ⚠ **[`PREEMPTS`] above is counted so that DELETING THIS LINE IS CAUGHT**, and it is counted
    // there rather than here for exactly that reason. Removing this call originally left the gate
    // fully GREEN: the retire path's own sweep still rescued the blocked vCPU at teardown, after
    // starving it for the whole boot. Measured red now at `2 wake sweeps against 218 preemptions`.
    wake_blocked_vcpus(hv);

    let next = match next_runnable(hv, cur) {
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
    sched_on(
        hv,
        slot_dom(next.guest()),
        scheduler_run(next, now),
        "run the next vcpu",
    );
    drop(cell);

    switch_context(cur.now_leaving(), next, frame);
}

/// Which guest's half of the RAM window contains `ipa`, if any (③-b2b-ii-d).
///
/// Derived from the same `first_frame`/`LINUX_SUP_FRAMES_PER_GUEST` split the model ownership and
/// the emitted images come from, so "whose memory is this" has one answer on this path and it is the
/// one the emitter used.
fn guest_owning(ipa: u64) -> Option<usize> {
    // ㉒: the containment test is `hv-part`'s, and `owner_of` is PROVEN to be exactly the
    // inverse of the window map (both directions — a version that always answered "nobody" would
    // pass a soundness-only harness, and the completeness arm was probe-confirmed to catch it).
    PARTITION.owner_of(ipa).map(|slot| slot as usize)
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
/// working.
///
/// ## The cap, its ORIGINAL reason (now obsolete), and what exceeding it does
///
/// [`MAX_PEER_FAULTS`] was written "so a guest that loops on it cannot spin EL2 forever". **That
/// justification no longer stands, and re-deriving it is what changed this rung**: ③-b2b-ii-e gave
/// EL2 its own `CNTHP` clock, which the guest can neither program nor mask, so a guest looping on
/// peer faults cannot hold the pCPU whatever the cap says. It makes no progress and its PEER keeps
/// running. Liveness is the slice's job now.
///
/// What the cap is still good for is the DIAGNOSTIC — *this guest is not probing, it is looping* —
/// so it stays. What changed is the ACTION. **Exceeding it used to `crate::park()`, and a guest could
/// reach that with a two-instruction loop** (fault on a peer address, be skipped by the very line
/// below, resume, repeat), which halted the machine and killed the innocent peer with it. It now
/// retires the looping domain and hands the pCPU on — the same answer, and the same machinery, as
/// every other guest fault on this path.
///
/// ⚠ This was the **ninth** guest-reachable halt, and the sweep that found the other eight MISSED
/// it: it appeared in that sweep's park-to-function mapping and was dropped when the summary table
/// was written. When an audit produces both a list and a table, diff them.
fn handle_peer_fault(
    faulting: usize,
    owner: usize,
    ipa: u64,
    frame: &mut LinuxFrame,
    uart: &mut Pl011,
) {
    let n = PEER_FAULTS.at(faulting).fetch_add(1, Ordering::Relaxed) + 1;
    if n > MAX_PEER_FAULTS {
        let _ = writeln!(
            uart,
            "baleen: guest FAULT: dom {} has faulted on dom {}'s memory {n} times (cap \
             {MAX_PEER_FAULTS}) — it is not probing, it is looping",
            slot_dom(faulting),
            slot_dom(owner)
        );
        fault_retire(current_vcpu(), frame, uart, "looped on its peer's memory");
        return;
    }

    // Only the first one is reported in full: the AMBA identification read produces a fixed handful
    // of these, and eight identical paragraphs would bury the boot's other output.
    if n == 1 {
        let peer_l1 = hv_s2::arm64::vttbr_table(VTTBR.at(owner).load(Ordering::Relaxed));
        let mine_l1 = hv_s2::arm64::vttbr_table(VTTBR.at(faulting).load(Ordering::Relaxed));
        let in_peer = stage2::walk_stage2(peer_l1, ipa);
        let in_mine = stage2::walk_stage2(mine_l1, ipa);
        let identity = in_peer.map(|r| r.pa == ipa).unwrap_or(false);
        // ★ **"The peer's own payload is sitting there" — asked of whichever payload the peer has.**
        //
        // This third conjunct is what makes the refusal mean something: an address that is merely
        // unmapped for the toucher and empty for its owner would fault for a boring reason. It used
        // to read the `ARM\x64` header, which asked "is a LINUX KERNEL there" — a question with a
        // right answer only while every slot ran Linux. Under the `monitor` configuration the peer's
        // window holds a bare-metal payload, and the check FAILED on a machine that was working
        // exactly as designed (measured, on the first boot of that configuration).
        //
        // ⚠ **The general question was always the one worth asking**, and the kernel magic was a
        // narrow instance of it that happened to be total. What is checked now is that the owner's
        // window holds *what EL2 deposited in it*, which is the same claim for a kernel and strictly
        // better evidence for the monitor: the monitor's word is read back out of the template
        // rather than compared against a constant.
        let (payload_present, observed) = peer_payload_at(owner);

        if in_mine.is_none() && identity && payload_present {
            let _ = writeln!(
                uart,
                "baleen: peerfault OK: dom {} touched dom {}'s memory at IPA 0x{ipa:08x} and the \
                 HARDWARE refused it — that address is unmapped in dom {}'s image, resolves to \
                 itself in dom {}'s live emitted image, and dom {}'s own loaded payload ({}) is \
                 sitting there right now; dom {} took the abort and kept running",
                slot_dom(faulting),
                slot_dom(owner),
                slot_dom(faulting),
                slot_dom(owner),
                slot_dom(owner),
                payload_name(owner),
                slot_dom(faulting)
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: peerfault FAIL: dom {} faulted at IPA 0x{ipa:08x}, but the refusal proves \
                 nothing — mapped in its own image: {}; resolves to itself in dom {}'s: {}; dom \
                 {}'s {} signature there: 0x{observed:08x}",
                slot_dom(faulting),
                in_mine.is_some(),
                slot_dom(owner),
                identity,
                slot_dom(owner),
                payload_name(owner)
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
static RETIREMENT: PerGuest<AtomicU64, NUM_GUESTS> =
    PerGuest::new([const { AtomicU64::new(0) }; NUM_GUESTS]);

fn set_retirement(slot: usize, why: Retirement) {
    RETIREMENT.at(slot).store(
        match why {
            Retirement::Live => 0,
            Retirement::PoweredOff => 1,
            Retirement::Faulted => 2,
        },
        Ordering::Relaxed,
    );
}

fn retirement_of(slot: usize) -> Retirement {
    match RETIREMENT.at(slot).load(Ordering::Relaxed) {
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
    cur: Running,
    frame: &mut LinuxFrame,
    uart: &mut Pl011,
    why: Retirement,
) -> bool {
    set_retirement(cur.guest(), why);
    let Some(mut cell) = crate::guest::GUEST_HV.try_borrow_mut() else {
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: dom {} retired while the model was borrowed; halting",
            slot_dom(cur.guest())
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
    // ★★ ⑱-4b-ii — **RETIRE EVERY vCPU THE GUEST HAS.** ⑱-3b-ii left this offlining only the vCPU
    //          that was running and said, in as many words, that it was "the one place this rung
    //          leaves a loaded gun": the moment `CPU_ON` admits a second vCPU, retiring a guest
    //          would leave a sibling `Runnable`, and `next_runnable` would go on handing the pCPU to
    //          a vCPU of a domain that has powered off.
    //
    // A domain teardown is a claim about the DOMAIN, so it has to reach every vCPU the domain owns.
    //
    // ⚠ **`hv_core::sched::offline_all` is exactly this and is deliberately NOT used**, because it
    // is reachable only through `HvCall::DomainDestroy` — and destroying is a different transition
    // from retiring, one this file argues against making (see the doc above: `SchedOffline` "is the
    // truthful transition"; a kernel that has issued `SYSTEM_OFF` has not been destroyed, and its
    // domain must stay `Live` for the peer-fault path to keep resolving against its image). So the
    // metal applies the model's own per-vCPU transition to each vCPU it knows the guest has. That is
    // ITERATION over one transition, not a second derivation of what offlining means.
    //
    // The `state_of` filter is not defensive: `SchedOffline` refuses an already-`Offline` vCPU with
    // `WrongState` and [`sched_on`] halts on a refusal — correctly, since a refusal means this
    // file's idea of who is running has come apart from the model's. Asking first is how a vCPU that
    // never started is SKIPPED rather than treated as an inconsistency. It is the same filter
    // `offline_all` applies internally, for the same reason.
    // ⑱-8: this guest's vCPUs as a role. The `.filter(|&(g, _)| g == cur.guest())` this replaces was
    // the fourth and last instance of the idiom — and the one whose failure would be quietest, since
    // offlining a PEER's vCPU is a `WrongState` refusal from the model rather than anything visible.
    for own in cur.own_vcpus() {
        let v = own.vcpu();
        let state = hv.sched().state_of(slot_dom(cur.guest()), v.model());
        if state == Some(RunState::Offline) {
            continue;
        }
        // ⑱-4b-ii — a sibling asleep in `wfi` when its domain powers off leaves `Blocked` by being
        // RETIRED rather than woken. Counted so ⑱-4b-i's conservation law still balances; see
        // [`VCPUS_OFFLINED_WHILE_BLOCKED`], which the first boot of this rung is what created.
        if state == Some(RunState::Blocked) {
            VCPUS_OFFLINED_WHILE_BLOCKED
                .own(own)
                .fetch_add(1, Ordering::Relaxed);
        }
        sched_on(
            hv,
            slot_dom(cur.guest()),
            HvCall::SchedOffline {
                vcpu: v.model(),
                now,
            },
            "retire a vcpu of a domain that is going down",
        );
    }
    // ★★ ⑱-4b-i — **WAKE BEFORE CONCLUDING THE MACHINE IS FINISHED. This rung introduces the hazard
    //          this line closes, so the two are inseparable.**
    //
    // `next_runnable` returning `None` used to mean exactly one thing — every vCPU is `Offline`, so
    // the boot is over — because `Offline` was the only state that made a vCPU un-runnable. Making
    // `wfi` produce `Blocked` adds a second, and it is emphatically **not** "finished": it is
    // "asleep, and nobody has rung the bell yet".
    //
    // Left alone, the failure is EL2 ending the boot out from under a guest that was merely idle:
    // dom 1 blocks, dom 2 powers off, `None` comes back, and `end_of_boot` runs while dom 1's kernel
    // is still mid-`sleep` and has never issued `SYSTEM_OFF`. The `retire dom N: never retired`
    // conjunct is what would catch it, but catching it is not the same as it not happening.
    //
    // So the question "is anyone left?" has to be asked of vCPUs that COULD run, not of ones that
    // happen to want the pCPU this instant. Waking first turns the second question into the first,
    // and a `None` after it is once again the honest "everything is `Offline`".
    wake_blocked_vcpus(hv);
    let Some(next) = next_runnable(hv, cur) else {
        return false;
    };
    sched_on(
        hv,
        slot_dom(next.guest()),
        scheduler_run(next, now),
        "run the surviving vcpu",
    );
    drop(cell);
    switch_context(cur.now_leaving(), next, frame);
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
fn fault_retire(cur: Running, frame: &mut LinuxFrame, uart: &mut Pl011, what: &str) {
    CONSOLE.borrow_mut().flush(cur.guest(), uart);
    let _ = writeln!(
        uart,
        "baleen: dom {} RETIRED — {what}. The domain is stopped; the machine is not.",
        slot_dom(cur.guest())
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
    report_idle(uart);
    report_guest_identity(uart);
    report_vcpu_census(uart);
    report_fp_isolation(uart);
    report_active_priorities(uart);
    report_pending_absorption(uart);
    report_sgi_routing(uart);
    #[cfg(feature = "selftest")]
    report_lr_overflow(uart);
    #[cfg(feature = "selftest")]
    report_tick_deferral(uart);
    report_per_guest_state(uart);
    report_scrub_line(uart);
    report_dma_pad(uart);
    #[cfg(feature = "smmu")]
    report_dma_inflight(uart);
    if (0..NUM_GUESTS).all(|s| retirement_of(s) == Retirement::PoweredOff) {
        let _ = writeln!(
            uart,
            "baleen: every partition has powered off — {NUM_LINUX} unmodified kernel(s) and \
             {NUM_MONITOR} bare-metal monitor partition(s) ran isolated on hv-metal's EL2, \
             time-slicing one pCPU, and shut down through the same PSCI SYSTEM_OFF path (M5 Arc 5e)"
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

/// **The tick-deferral witness** — a full bank defers the forwarded timer instead of halting.
///
/// Reports the count for every guest, and ASSERTS only that the manufactured deferral actually
/// happened somewhere. The per-guest count itself is not assertable: which guest holds the pCPU when
/// the one-shot fires is a scheduling accident, and a boot where the OTHER guest saw it is just as
/// correct — a count tied to which domain got it would be a claim about the workload.
#[cfg(feature = "selftest")]
fn report_tick_deferral(uart: &mut Pl011) {
    let total: u64 = (0..NUM_GUESTS)
        .map(|s| TIMER_DEFERRED.at(s).load(Ordering::Relaxed))
        .sum();
    if total > 0 {
        let _ = writeln!(
            uart,
            "baleen: tickdefer OK: a FULL list-register bank DEFERS the forwarded timer instead of \
             halting — {total} tick(s) could not be placed, EL2 left the PPI Active with a priority \
             drop only, and the still-expired CNTV_CVAL_EL0 re-asserted it after the next handover. \
             The guest that filled its own bank went one round without a tick; the peer was untouched"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: tickdefer FAIL: no forwarded tick was ever deferred — the probe never \
             manufactured a full bank, so a full bank halting the machine would look exactly like \
             this boot"
        );
    }
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

fn power_off_and_hand_over(cur: Running, frame: &mut LinuxFrame, uart: &mut Pl011) -> bool {
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
/// The rotation order — peer preferred, caller as the fallback — lives in
/// [`Running::rotation`](crate::role::Running::rotation), together with the note that the ORDER is
/// policy and becomes a real question at ⑱-4.
///
/// ## ★ ⑱-3b-ii — it selects a `(guest, vCPU)` PAIR, and the model is what refuses the second one
///
/// The candidate axis is now both. **Nothing else had to change to keep vCPU 1 off the pCPU**, and
/// that is the rung's whole safety argument: `hv-core` boots every vCPU `Offline`, the metal admits
/// only the boot one, and the `find` below tests `state_of(..) == Some(Runnable)`. So an unseeded
/// vCPU is offered on every rotation and refused every time **by the model's own run state** — not
/// by a guard this file wrote, not by a range this file kept, and not by the axis being absent.
///
/// That distinction is the reason this rung is safe to land before ⑱-4 seeds vCPU 1: dispatching it
/// would `eret` into a zeroed [`vcpu::VcpuCtx`] at PC = 0. The thing standing between here and that
/// is a proven state machine answering a question, which is exactly where such a thing should stand.
fn next_runnable(hv: &Hypervisor, cur: Running) -> Option<Incoming> {
    cur.rotation(NUM_GUESTS)
        .find(|&(slot, vcpu)| {
            hv.sched().state_of(slot_dom(slot), vcpu.model()) == Some(RunState::Runnable)
        })
        .map(|(slot, vcpu)| Incoming::at(slot, vcpu))
}

/// The `SchedRun` that dispatches a guest's vCPU onto the one physical CPU.
///
/// **It takes no slot, and that is still the interesting part.** A vCPU id is scoped to its *domain*
/// in `hv_core::sched`, so which GUEST is being run is carried entirely by the domain the call is
/// dispatched on behalf of ([`sched_on`]'s `dom`), and every dispatch names [`PCPU0`]. A `slot`
/// parameter here would look like it selected something.
///
/// ⑱-3b-ii adds the one parameter that **does** select something. This used to read
/// `vcpu: LINUX_VCPU` — a constant, correct while a guest had one vCPU, and the same defect shape
/// ⑱-3b-i spent a rung removing from six other sites. It takes the [`Incoming`] rather than a bare
/// index so the vCPU it dispatches is provably the one the scheduler chose, and the pair cannot come
/// apart: the domain below and the vCPU here are two halves of one selection.
fn scheduler_run(next: Incoming, now: hv_hal::Ticks) -> HvCall {
    HvCall::SchedRun {
        vcpu: next.vcpu().model(),
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
/// leaving: its slice starts here. ⑱-1 adds a second such step (5b′): the incoming vCPU's
/// **identity**, written beside its address space because both are EL2-owned configuration
/// describing the guest about to run rather than state that guest owns.
/// ⚠ **The two parameters are DIFFERENT TYPES on purpose** — see [`crate::role`]. Both were
/// `usize`, and two of the eighteen indexed uses below could be swapped with the boot gate
/// staying green (MEASURED). A swap is now a compile error.
fn switch_context(cur: Outgoing, next: Incoming, frame: &mut LinuxFrame) {
    let mut ctx = VCPU_CTX.borrow_mut();
    // 1. Capture the outgoing vCPU, list registers and `CNTV_CVAL_EL0` included.
    ctx.out_mut(cur).save(&frame.x);

    // 2. Demote its forwarded interrupts, and 3. hand the physical timer back. Between them these
    //    are the whole of Probe 0's fix: the outgoing guest keeps its pending tick as a purely
    //    VIRTUAL interrupt, and the one physical PPI on this machine stops being Active so it can be
    //    signalled to whoever runs next. See `gic::release_forwarded_timer` for the measurement that
    //    forced this and for why disable must precede deactivate.
    HANDOVERS.out(cur).fetch_add(1, Ordering::Relaxed);
    let released = ctx.out_mut(cur).release_hardware_mappings();
    HW_RELEASED.out(cur).fetch_add(released, Ordering::Relaxed);
    if gic::release_forwarded_timer() {
        TIMER_DEACTIVATED.out(cur).fetch_add(1, Ordering::Relaxed);
    }

    // 3b. ③-b2b-ii-f — **whose data is in the FP register file right now?** `ctx.out_mut(cur).fp()` was read
    //     off the hardware in step 1, so this compares the live file against what the INCOMING vCPU
    //     last owned. Different means the incoming guest was about to read its peer's `v0..v31` —
    //     which, before this rung, is exactly what it did. Taken here because step 4 is about to
    //     destroy the evidence.
    let incoming_fp = ctx.inc_mut(next).fp();
    if ctx.out_mut(cur).fp() != incoming_fp {
        FP_FOREIGN.inc(next).fetch_add(1, Ordering::Relaxed);
    }

    // 3b′. ⑱-4a — **and whose ACTIVE PRIORITIES is the virtual interface carrying?** Read off the
    //      hardware rather than out of the outgoing context, because unlike the FP file this state
    //      is not merely *stale* when it is wrong: a priority the outgoing vCPU acknowledged and has
    //      not ended is a live veto on everything the incoming one could be signalled. Taken here
    //      for the same reason the FP read is — step 4 is about to destroy the evidence.
    let incoming_apr = ctx.inc_mut(next).active_priorities();
    if gic::live_active_priorities() != incoming_apr {
        AP_FOREIGN.inc(next).fetch_add(1, Ordering::Relaxed);
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
    unsafe { ctx.inc_mut(next).poison() };

    // ⑱-4b-ii — **THE GUARD, placed where the damage would be done rather than where it originates.**
    //
    // Restoring a vCPU with no seeded context loads a zeroed [`vcpu::VcpuCtx`] and `eret`s to PC = 0.
    // ⑱-3b-ii measured exactly that (`EC=0x20 ELR=FAR=0x0`, both guests retired, the boot never
    // finishing) by admitting every vCPU as a probe.
    //
    // **Nothing a GUEST can do reaches here** — [`cpu_on`] seeds before it admits, so the inversion
    // is unreachable rather than merely caught, and only an EL2 bug could admit a vCPU it never
    // seeded. That is precisely why this parks instead of recovering, for the same reason
    // [`sched_on`] does: a failure here is never a guest's fault and never something to continue
    // through. The ordering in `cpu_on` is the safety property; this is the alarm on it.
    if VCPU_SEEDED.inc(next).load(Ordering::Relaxed) == 0 {
        let mut uart = crate::uart();
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: about to enter a vCPU with NO SEEDED CONTEXT — its saved \
             state is all zero, so this would eret to PC = 0. hv-core admitted a vCPU hv-metal \
             never gave a context to; halting instead of running it"
        );
        crate::park();
    }

    // 5. Install the incoming vCPU. **Only now** does `CNTV_CTL_EL0`/`CNTV_CVAL_EL0` describe the
    //    guest about to run, which is why step 6 cannot be folded into step 3: re-arming the PPI
    //    while the outgoing guest's deadline was still loaded would fire the outgoing guest's timer
    //    into the incoming one.
    // SAFETY: at EL2, restoring the context of the vCPU about to be resumed. For guest B's FIRST
    // switch-in this is the arm64 boot protocol's entry state, seeded by `VcpuCtx::seed_boot` — so
    // B's boot and B's resume are the same instruction, not two paths that must agree.
    unsafe { ctx.inc_mut(next).restore(&mut frame.x) };
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
    crate::guest::set_vttbr_no_flush(VTTBR.inc(next).load(Ordering::Relaxed));

    // 5b′. ⑱-1 — and the incoming vCPU's IDENTITY, next to its address space because they are the
    //      same kind of thing: EL2-owned configuration that describes the guest about to run rather
    //      than state the guest owns. Written on every switch-in and not once at boot, because at
    //      ⑱-3 the answer stops being constant — a boot-time write would then be silently stale for
    //      every vCPU but the first.
    //
    //      ⚠ **⑱-3b-i: and it was constant ANYWAY.** The line above is ⑱-1's, and it is correct
    //      about the hazard, in the right place, a rung early. The call underneath it still read
    //      `set_guest_identity(BOOT_VCPU)` — a write on every switch-in, of vCPU 0's identity, to
    //      whichever vCPU was arriving. The comment described the fix and the code did not implement
    //      it, and nothing in the build, the gate or five metal-lint configs could tell. That is the
    //      argument for the parameter now being an `Incoming`.
    set_guest_identity(next);

    // 5c. ③-b2b-ii-f — read the FP file back off the hardware and confirm it is the incoming vCPU's.
    //     Structural: true on every switch regardless of what any guest does, which is what makes it
    //     assertable where `FP_FOREIGN` is not. Verifying here rather than immediately after step 5
    //     costs nothing: `set_vttbr_no_flush` touches no floating-point state.
    let mut live = crate::fp::FpCtx::ZERO;
    live.save();
    if live == incoming_fp {
        FP_RESTORE_VERIFIED
            .inc(next)
            .fetch_add(1, Ordering::Relaxed);
    }

    // 5c′. ⑱-4a — the same question of the active priorities, and the same answer: ask the
    //      interface, do not trust the write. "EL2 wrote it" and "the machine holds it" are the two
    //      facts `gic::release_forwarded_timer` already taught this file to keep apart.
    if gic::live_active_priorities() == incoming_apr {
        AP_RESTORE_VERIFIED
            .inc(next)
            .fetch_add(1, Ordering::Relaxed);
    }

    // 5d. Drain the incoming guest's pending set into its now-restored bank. It must run AFTER the
    //     restore (which overwrites the whole bank, so a pre-restore refill would be discarded), and
    //     it re-arms `UIE` for whatever is still pending — which is also what makes the arming follow
    //     the switched-IN vCPU rather than the outgoing one.
    let _ = flush_pending_to_lrs(LINUX_PENDING.inc(next), SGIS_DRAINED.inc(next));

    // 6. Re-arm the physical PPI for the INCOMING guest, according to its own emulated distributor —
    //    the same mediation seam `handle_vgic_access` mirrors, applied at the other moment the
    //    answer can change. A guest running with its timer masked stays masked; one that wants it
    //    gets it, and gets it immediately, because its restored deadline has long since passed.
    //
    //    ⑱-3b-i: `next.vcpu()`, because INTID 27 is a PPI and the GICv3 banks 0..31 **per
    //    redistributor** (⑱-2). Both halves of this read have to name the arriving vCPU: reading the
    //    incoming guest's distributor with vCPU 0's bank would re-arm the physical timer according
    //    to a sibling's mask, which is silent in both directions — a masked vCPU kept ticking, or an
    //    unmasked one that never does.
    let wants_timer = VGIC
        .borrow_mut()
        .inc_mut(next)
        .is_enabled(next.vcpu(), gic::VTIMER_INTID);
    gic::set_ppi_enabled(gic::VTIMER_INTID, wants_timer);

    // 7. The pCPU now belongs to `next`, so every handler that asks "which guest?" must get the new
    //    answer from here on. Stored LAST: everything above still had to speak about `cur`.
    // The incoming guest becomes the running one — one of the TWO sanctioned role transitions
    // (⑱-3b-ii added `Running::now_leaving`, the outgoing counterpart).
    CURRENT.store(next.now_running().pack(), Ordering::Relaxed);
    SWITCHES.inc(next).fetch_add(1, Ordering::Relaxed);
    // ⑱-3b-ii's boundary, counted at the ONE funnel every switch passes through. See
    // [`DISPATCHED_NONBOOT`]: it stayed zero until ⑱-4b-ii seeded a second vCPU, and is now the
    // rung's headline — REPORTED, never asserted (low hundreds per boot; 344 and 378 on two runs).
    if !next.vcpu().is_boot() {
        DISPATCHED_NONBOOT.fetch_add(1, Ordering::Relaxed);
    }

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
                // ⑱-4b-ii adds `CPU_ON`. ⚠ **MEASURED that the shipped guest never asks:** with
                // `cpu@1` present and `CPU_ON` still unimplemented, Linux called the FID directly
                // and read its return code — it never queried `PSCI_FEATURES` for it. So this arm
                // is correctness for a caller that does, not something any boot exercises, and it
                // is written that way deliberately rather than left to be discovered.
                frame.x[0] = if frame.x[1] == PSCI_SYSTEM_OFF_FID || frame.x[1] == PSCI_CPU_ON_FID {
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
                // The FID is shared, so the sentence must name what actually retired. Saying "a real
                // Linux kernel" over a bare-metal partition would be a false claim in the transcript
                // the gate reads, made by the one code path both payloads deliberately share.
                let _ = writeln!(
                    uart,
                    "baleen: dom {} issued PSCI SYSTEM_OFF — {} on hv-metal's EL2",
                    slot_dom(cur),
                    if runs_linux(cur) {
                        "a real Linux kernel booted and shut down"
                    } else {
                        "the bare-metal monitor partition ran and shut down"
                    }
                );
                // ③-b2b-ii-c2: one guest powering off is no longer the end of the machine. Retire
                // it in the MODEL and hand the physical CPU to whoever is still Runnable; only when
                // nothing is does the boot end.
                if power_off_and_hand_over(current_vcpu(), frame, &mut uart) {
                    return;
                }
                end_of_boot(&mut uart);
            }
            // ★★ ⑱-4b-ii — **`CPU_ON`: a guest asks for its second CPU, and EL2 gives it one.**
            //
            // The arc's headline arrives here. Everything before it built the machinery for a vCPU
            // that could not be started — a per-vCPU redistributor (⑱-2), a typed vCPU axis (⑱-3a/b),
            // a scheduler that picks `(guest, vCPU)` (⑱-3b-ii), routed SGIs (⑱-5), per-vCPU active
            // priorities (⑱-4a), an idle vCPU that stops being a candidate (⑱-4b-i). This is the
            // call that starts it.
            //
            // MEASURED before implementing: each guest issues this **exactly once**, with
            // `x1 = 0x1`, `x2` an address in its OWN RAM, and `x3 = 0`; told `NOT_SUPPORTED` it
            // prints `psci: failed to boot CPU1 (-95)` and settles for one CPU.
            PSCI_CPU_ON_FID => {
                let (target_mpidr, entry, context_id) = (frame.x[1], frame.x[2], frame.x[3]);
                frame.x[0] = cpu_on(current_vcpu(), target_mpidr, entry, context_id, &mut uart);
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
        current_vcpu(),
        frame,
        &mut uart,
        "took an exception EL2 has no rule for",
    );
}

/// **⑱-4b-ii — service `PSCI CPU_ON`.** Returns the PSCI status to place in the caller's `x0`.
///
/// ## Which vCPU did the caller name, and the inversion that keeps ONE derivation
///
/// `x1` is a target **MPIDR**, not a vCPU index, so EL2 has to invert the map it presents. It does
/// that by **searching** — offering each of the caller's own vCPUs to [`guest_mpidr`] and comparing
/// under [`MPIDR_HWID_BITMASK`], which is exactly the comparison arm64 Linux's
/// `smp_setup_processor_id` and `gic_populate_rdist` make.
///
/// **A closed-form inverse would be a second derivation** of a mapping ⑱-3b-i spent a rung reducing
/// to one (it was two, in two crates, with a doc claiming otherwise), and it would silently stop
/// agreeing the day the affinity encoding gains structure. Searching `VCPUS_PER_GUEST` entries to
/// avoid that is not a cost worth optimising.
///
/// ⚠ **The search returns THE vCPU and not merely A vCPU because affinities are provably distinct**
/// — [`AFFINITIES_ARE_DISTINCT`], a compile-time pairwise check over the whole axis. Without it a
/// duplicate affinity would make this silently resolve to whichever came first. That obligation was
/// recorded by ⑱-3b-i, came due at ⑱-3b-ii, and is discharged by this rung because this is where it
/// became load-bearing.
///
/// ## The three refusals, and why each is an ANSWER rather than a fallback
///
/// * **`INVALID_PARAMETERS`** — no vCPU *of this guest* has that MPIDR. Note the confinement: the
///   census is filtered to the caller's own slot, so a guest naming its peer's CPU is told its
///   parameters are invalid rather than being allowed to learn whether that CPU exists.
/// * **`ALREADY_ON`** — the model does not say `Offline`. **The model is asked; no flag is kept
///   here**, which is the discipline [`next_runnable`] follows for the same reason: `hv-core` owns
///   run state and a second copy in this file would be a thing to keep in step.
/// * **`INVALID_ADDRESS`** — the entry point is not in the caller's own RAM, decided by
///   [`guest_owning`], the same function the peer-fault path and the emitter's split come from.
///   ⚠ **This is FIDELITY, not enforcement, and the distinction is worth keeping straight.** Stage-2
///   already confines the secondary: an entry point in the peer's RAM is unmapped in this guest's
///   image and faults on the first fetch. What the check buys is that the guest is *told*, in the
///   architected way, instead of being started and dying. MEASURED: the shipped boot never trips it
///   — both guests pass an address in their own window, at the same offset from their own base.
///
/// ## ★ THE PROBES, and the first one REFUTED THE PREDICTION MADE FOR IT
///
/// | # | probe | predicted | measured |
/// |---|---|---|---|
/// | A | **invert the order** — `SchedAdmit` before seeding | kills | **did NOT kill — gate fully GREEN** |
/// | A′ | admit and **never seed at all** | kills | **kills**, and `EC=0x20 ELR=0x0` never happens |
/// | B | retire only the RUNNING vCPU (⑱-3b-ii's code) | kills | **kills** |
/// | C | make two vCPUs share an affinity | `E0080` | **`E0080` ×2, before anything runs** |
/// | D | answer `NOT_SUPPORTED` again | kills | **kills** |
///
/// **Probe A is the one worth reading.** "Seed before admit" is stated above as the safety property,
/// and reversing it changes nothing observable: EL2 is not preemptible between the two statements on
/// a single pCPU, so no dispatch can occur in the window the inversion opens. **The ordering is
/// insurance against a concurrent EL2 — which is also why `ON_PENDING` is absent — and not against
/// today's machine.** Keeping it is still right; claiming today's boot depends on it would not be.
///
/// **What actually protects the machine is [`switch_context`]'s guard,** and probe A′ is its
/// evidence: admitting a vCPU with no context at all reddens all three configurations, and the count
/// of `EC=0x20 ELR=FAR=0x0` — ⑱-3b-ii's measured signature for an `eret` to PC = 0 — is **zero**.
/// The guard stops it *before* the `eret` rather than reporting it afterwards.
///
/// **Probe B** confirms retire-all is load-bearing exactly as ⑱-3b-ii predicted when it called this
/// "the one place this rung leaves a loaded gun": dom 1 retires, dom 2 powers off, and then neither
/// `retire dom 1` nor `retire dom 2` is ever printed, because the scheduler keeps handing the pCPU
/// to the retired domain's parked sibling and `end_of_boot` is never reached.
///
/// ## Honest ceiling
///
/// `ON_PENDING` is not modelled and cannot arise here: this hypervisor is single-pCPU and services
/// the `HVC` to completion before the caller resumes, so there is no window in which a vCPU is
/// "coming up". A concurrent EL2 would need it. And `CPU_OFF`/`CPU_SUSPEND` remain unimplemented —
/// `guest.dts` advertises `cpu_off`, and a guest calling it still gets `NOT_SUPPORTED`, so a guest
/// can start its second CPU but cannot stop it. Nothing in the shipped boot does.
fn cpu_on(
    running: Running,
    target_mpidr: u64,
    entry: u64,
    context_id: u64,
    uart: &mut Pl011,
) -> u64 {
    let slot = running.guest();
    let refuse = |why: &str, code: u64, uart: &mut Pl011| -> u64 {
        CPU_ON_REFUSED.at(slot).fetch_add(1, Ordering::Relaxed);
        let _ = writeln!(
            uart,
            "baleen: cpu_on: dom {} REFUSED (mpidr=0x{target_mpidr:x} entry=0x{entry:x}): {why}",
            slot_dom(slot)
        );
        code
    };

    // ★★ ⑱-8, and this is the SHARPEST of the four sites the role fence covers. `target_mpidr` is
    // `x1` of a PSCI call — **a value the guest chose** — and `guest_mpidr` is
    // `MPIDR_RES1 | vcpu_affinity(vcpu)`, which takes no guest argument. So a peer's vCPU with the
    // same index has the SAME MPIDR and matches `want` exactly. Before this rung, a
    // `.filter(|&(g, _)| g == slot)` was the only thing between a guest-chosen register value and
    // starting a vCPU that belongs to somebody else.
    //
    // `own_vcpus` has no peer to find, so the refusal below is now about a guest naming an MPIDR
    // *none of its own* vCPUs has — which is the only way it can legitimately fail.
    let want = target_mpidr & MPIDR_HWID_BITMASK;
    let Some(own) = running
        .own_vcpus()
        .find(|o| guest_mpidr(o.vcpu()) & MPIDR_HWID_BITMASK == want)
    else {
        return refuse(
            "no vCPU of this guest has that MPIDR",
            PSCI_INVALID_PARAMETERS,
            uart,
        );
    };

    if guest_owning(entry) != Some(slot) {
        return refuse(
            "the entry point is not in this guest's own RAM",
            PSCI_INVALID_ADDRESS,
            uart,
        );
    }

    let Some(mut cell) = crate::guest::GUEST_HV.try_borrow_mut() else {
        let _ = writeln!(
            uart,
            "baleen: LINUX GUEST TRAP: CPU_ON arrived while the model was borrowed; halting"
        );
        crate::park();
    };
    let Some(hv) = cell.as_mut() else {
        crate::park();
    };
    if hv.sched().state_of(slot_dom(slot), own.vcpu().model()) != Some(RunState::Offline) {
        drop(cell);
        return refuse("that vCPU is not Offline", PSCI_ALREADY_ON, uart);
    }

    // ★ **SEED FIRST.** `SchedAdmit` is what makes a vCPU eligible for [`next_runnable`]; a vCPU
    //   that becomes eligible before it has a context is one the scheduler may dispatch into a
    //   zeroed `VcpuCtx` and `eret` to PC = 0, which ⑱-3b-ii measured directly.
    //
    //   ⚠ **This used to claim the ORDER was the safety property. PROBE A REFUTED THAT** — inverting
    //   these two statements leaves the gate fully green, because EL2 is not preemptible between
    //   them on a single pCPU and nothing can dispatch in the window. The order is kept as insurance
    //   against a concurrent EL2 (the same reason `ON_PENDING` is absent), and what actually
    //   protects the machine is [`switch_context`]'s guard — probe A′, which reddens all three
    //   configurations and never reaches the `eret`. See the probe table on [`cpu_on`].
    VCPU_CTX.borrow_mut().own_mut(own).seed_boot(
        entry,
        context_id,
        SPSR_EL2_LINUX,
        SCTLR_AT_BOOT.load(Ordering::Relaxed),
    );
    VCPU_SEEDED.own(own).store(1, Ordering::Relaxed);
    SECONDARIES_SEEDED.at(slot).fetch_add(1, Ordering::Relaxed);

    sched_on(
        hv,
        slot_dom(slot),
        HvCall::SchedAdmit {
            vcpu: own.vcpu().model(),
        },
        "admit a secondary vcpu started by PSCI CPU_ON",
    );
    drop(cell);
    SECONDARIES_ADMITTED
        .at(slot)
        .fetch_add(1, Ordering::Relaxed);

    let _ = writeln!(
        uart,
        "baleen: cpu_on OK: dom {} started vCPU {} at 0x{entry:08x} (x0 = context_id \
         0x{context_id:x}, SPSR 0x{SPSR_EL2_LINUX:x}, SCTLR_EL1 0x{:x} — MMU off, as its boot vCPU \
         was) — SEEDED BEFORE ADMITTED, and it becomes Runnable only in hv-core",
        slot_dom(slot),
        own.vcpu().get(),
        SCTLR_AT_BOOT.load(Ordering::Relaxed)
    );
    PSCI_SUCCESS
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
    // ⑱-3b-ii: one read of `CURRENT`, under both names. `faulting` indexes per-guest state (the
    // RAM-window owner check, the console); `running` is what the retire path needs, because
    // retiring hands the pCPU on and that is a `(guest, vCPU)` decision.
    let running = current_vcpu();
    let faulting = running.guest();
    // ㉗ — **the write kill-probe, recognised BEFORE the peer-fault path.** The monitor's view is
    // read-only, so a store through it is a Stage-2 PERMISSION fault at an IPA the monitor really
    // does map — which `handle_peer_fault` would report as "the refusal proves nothing" and park on,
    // because its whole argument is built on the address being unmapped for the toucher. Both are
    // "a guest touched its peer's memory and the hardware refused", and they are entirely different
    // claims; this is the one place they have to be told apart.
    #[cfg(feature = "monitor")]
    if !runs_linux(faulting) && ipa & !(stage2::SUP_FRAME_BYTES - 1) == OBSERVED_IPA {
        handle_observation_fault(faulting, ipa, a.wnr, frame, uart);
        return;
    }
    if let Some(owner) = guest_owning(ipa) {
        if owner != faulting {
            handle_peer_fault(faulting, owner, ipa, frame, uart);
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
            running,
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
        fault_retire(running, frame, uart, "made an undecodable PL011 access");
        return;
    }
    let offset = ipa - vpl011::VPL011_BASE;
    if !offset.is_multiple_of(a.access_bytes()) {
        let _ = writeln!(
            uart,
            "baleen: guest FAULT: misaligned PL011 access at IPA=0x{ipa:016x} ({} bytes)",
            a.access_bytes()
        );
        fault_retire(running, frame, uart, "made a misaligned PL011 access");
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
            current_vcpu(),
            frame,
            uart,
            "made an undecodable GIC access",
        );
        return;
    }

    // ⑱-3b-i: the whole role. The MMIO decode below is per-GUEST (one distributor, whichever vCPU
    // is driving it), but the timer mirror at the end of this function is per-VCPU, and it used to
    // read `BOOT_VCPU` — see [`crate::role::VcpuIdx`].
    let running = current_vcpu();
    let slot = running.guest();
    let mut dev = VGIC.borrow_mut();
    let outcome = if a.wnr {
        let value = if a.srt < 31 { frame.x[a.srt] } else { 0 } & a.value_mask();
        dev.at_mut(slot)
            .mmio_write(ipa, a.access_bytes(), value)
            .map(|()| 0)
    } else {
        dev.at_mut(slot)
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
    //
    // ⑱-3b-i: the running **vCPU's** bank, for the same reason. There is one physical redistributor
    // for all of them, so what gets mirrored onto it must be the mask of the vCPU that is actually
    // going to run against it — not vCPU 0's, which is what this read named before.
    let timer_enabled = dev
        .at_mut(slot)
        .is_enabled(running.vcpu(), gic::VTIMER_INTID);
    // ⑱-6. Read where the guest has routed the witness SPI while the borrow is held, and act after
    // the drop. This ARMS the witness; the delivery happens elsewhere, and `maybe_fire_spi_witness`
    // is where the reason is written down.
    let spi_route = dev.at_mut(slot).spi_route(WITNESS_SPI);
    drop(dev);
    if a.wnr {
        gic::set_ppi_enabled(gic::VTIMER_INTID, timer_enabled);
        arm_spi_witness(running, spi_route);
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
            running,
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

/// ⑱-4b-i — how many times [`handle_linux_wfi`] moved a vCPU to `Blocked`.
///
/// **On the vCPU axis, not the guest axis, and that is not anticipation.** "Which vCPU said it had
/// nothing to do" is a per-vCPU fact in the most literal sense: the whole defect this rung closes is
/// two vCPUs of one guest being indistinguishable to a per-guest counter. Storing it per guest would
/// be the merged-count shape `TIMER_FORWARDED`'s own doc warns about, written fresh.
static VCPUS_BLOCKED: PerVcpu<AtomicU64, NUM_GUESTS, VCPUS_PER_GUEST> =
    PerVcpu::new([const { [const { AtomicU64::new(0) }; VCPUS_PER_GUEST] }; NUM_GUESTS]);
/// ⑱-4b-i — of those, how many the MODEL then reported as `Blocked` when asked.
///
/// The read-back, not the request. `sched_on` already halts if the model *refuses* the transition,
/// so this is not checking for an error — it is checking that the state the model is now in is the
/// one this file believes it put it in. Same discipline as `HCR_EL2`'s read-back in
/// [`trap_guest_wfi`]: ask the register what happened rather than assume the write took.
static BLOCKED_READBACK_OK: PerVcpu<AtomicU64, NUM_GUESTS, VCPUS_PER_GUEST> =
    PerVcpu::new([const { [const { AtomicU64::new(0) }; VCPUS_PER_GUEST] }; NUM_GUESTS]);
/// ⑱-4b-i — how many blocked vCPUs [`wake_blocked_vcpus`] returned to `Runnable`.
static VCPUS_WOKEN: PerVcpu<AtomicU64, NUM_GUESTS, VCPUS_PER_GUEST> =
    PerVcpu::new([const { [const { AtomicU64::new(0) }; VCPUS_PER_GUEST] }; NUM_GUESTS]);
/// ⑱-4b-ii — blocked vCPUs that were taken `Offline` by their domain retiring, rather than woken.
///
/// ★ **THIS COUNTER EXISTS BECAUSE ⑱-4b-i'S IDENTITY CAUGHT THIS RUNG.** That rung asserted
/// `woken == blocked` and was right to: with one vCPU per guest the retiring vCPU is always the
/// `Running` one, so no `Blocked` vCPU could ever be offlined and the third term was provably zero.
/// It was considered and left out as dead weight.
///
/// `CPU_ON` plus retire-all makes it reachable — a guest can power off while its *sibling* is asleep
/// in `wfi`, and [`retire_and_hand_over`] then offlines that sibling straight out of `Blocked`. The
/// first boot of this rung failed exactly there: **290 blocked, 289 woken.** One vCPU, off by one.
///
/// So the conservation law widens rather than weakens: every block is still accounted for, and the
/// two ways out of `Blocked` are now *woken* and *retired with its domain*.
static VCPUS_OFFLINED_WHILE_BLOCKED: PerVcpu<AtomicU64, NUM_GUESTS, VCPUS_PER_GUEST> =
    PerVcpu::new([const { [const { AtomicU64::new(0) }; VCPUS_PER_GUEST] }; NUM_GUESTS]);
/// ⑱-4b-i — how many times [`wake_blocked_vcpus`] ran a sweep, counted INSIDE the function.
///
/// ★ **Counted inside, and [`PREEMPTS`] outside, so that the two come apart when the CALL is
/// deleted.** A counter on the call site would vanish with the call and the identity would still
/// balance — which is the difference between a witness and a comment.
static WAKE_SWEEPS: AtomicU64 = AtomicU64::new(0);
/// ⑱-4b-i — how many times [`preempt_through_the_scheduler`] got far enough to preempt anything.
///
/// Incremented after the model borrow succeeds and independently of the sweep call, because it is
/// the *denominator* the sweep is checked against: every preemption must have swept first.
static PREEMPTS: AtomicU64 = AtomicU64::new(0);

/// **A guest went idle — give the pCPU to someone who can use it.**
///
/// The whole point of trapping `wfi`: see [`trap_guest_wfi`] for what happens without this.
///
/// [`next_runnable`] is consulted **before** the vCPU's own transition, and that is deliberate —
/// while this guest is still `Running` the model reports it as such, so the only slot that can come
/// back is a genuine *peer*. (The preemption path calls it after, where falling back to self is what
/// it wants.) `None` therefore means "nobody else can use the CPU", and the honest answer to that is
/// to wait, not to hand it back to a guest that has just said it has nothing to do.
///
/// ## ★ ⑱-4b-i KEPT THAT ORDER, and the alternative was written and rejected
///
/// The obvious way to add `Blocked` is to block first and then ask. **Don't** — asking first is what
/// keeps the no-peer case honest, and inverting it costs code that cannot run:
///
/// * **Ask first (this code).** No peer ⇒ the vCPU is still `Running`, so the existing
///   [`wait_at_el2`] path applies unchanged, down to the instruction. EL2 waits on its own `CNTHP`
///   slice, erets, and the guest re-executes its `wfi`. That path has ~100 runs of evidence behind
///   it from ③-b2b-ii-e and this rung does not disturb it.
/// * **Block first.** The model has already moved, so returning would `eret` into a vCPU the
///   scheduler says is `Blocked` — hv-metal's idea of who is running come apart from the model's,
///   which is the one thing [`sched_on`] exists to prevent. The no-peer case then needs its own
///   re-borrow, `SchedWake` and `SchedRun`-of-self. **That block is unreachable at one vCPU per
///   guest** — a guest going idle always leaves a peer guest `Runnable`, which is why every one of
///   the 8,735 traps measured below yielded — so it would ship unexecuted.
///
/// The livelock is broken identically either way, because what breaks it is a blocked *sibling*
/// ceasing to be returned by [`next_runnable`], not the order of the two calls here.
fn handle_linux_wfi(frame: &mut LinuxFrame) {
    // ⑱-3b-ii: the whole role. `WFI_TRAPS`/`WFI_YIELDS` are per-guest tallies and keep the slot; the
    // scheduler half below now names a `(guest, vCPU)` pair on both sides of the yield.
    let running = current_vcpu();
    let cur = running.guest();
    WFI_TRAPS[cur].fetch_add(1, Ordering::Relaxed);

    // ⑱-6 — the routed-SPI witness fires from here, and only from a vCPU the guest's routing does
    // NOT name. Before the yield, so the interrupt is waiting when its vCPU is next switched in.
    maybe_fire_spi_witness(running);

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
    let Some(peer) = next_runnable(hv, running) else {
        drop(cell);
        wait_at_el2();
        return;
    };
    let now = {
        use hv_hal::TimeSource;
        crate::time::GenericTimer.now()
    };
    // ★★ ⑱-4b-i — **`SchedBlock`, NOT `SchedPreempt`, and the difference is MEASURED.**
    //
    // `SchedPreempt` is `Running -> Runnable`: the vCPU gives up the pCPU and stays a candidate. For
    // a vCPU that has just executed `wfi` that is a lie of exactly one word — it does not want a
    // CPU, and `Runnable` says it does. The model has the right word (`Blocked`, *"waiting on an
    // event ... will not run until `System::wake` returns it to Runnable"*) and this file was not
    // using it.
    //
    // ⚠ **The cost of the lie, measured on `main` with both guests idle for one second:** dom 1 and
    // dom 2 trapped **8,735 `wfi`s each, and yielded on every single one** — the counts identical to
    // the unit, which is the signature of perfect alternation. Each guest went idle, `next_runnable`
    // handed the pCPU to the peer *because `SchedPreempt` had left the peer `Runnable`*, the peer was
    // also idle and handed it straight back. **17,613 full context switches** — 25 registers, the
    // vGIC bank and the FP file each — to accomplish two guests sleeping. Against **72** switches per
    // guest on a boot that never idles.
    //
    // It is a pathology and not a hang, which is exactly why it survived: the guests' own timer ticks
    // keep breaking the cycle, so `main` completes in the right wall-clock time while doing 122× the
    // work. **Safe by workload, not by construction** — the seventh instance in this arc.
    //
    // `Blocked` removes the candidacy rather than the symptom: `next_runnable` already filters on
    // `== Some(Runnable)`, so an idle peer stops being offered **for free**, with no flag this file
    // keeps and no second notion of idleness to drift from the model's.
    sched_on(
        hv,
        slot_dom(cur),
        HvCall::SchedBlock {
            vcpu: running.vcpu().model(),
            now,
        },
        "block a vcpu that executed WFI",
    );
    VCPUS_BLOCKED.of(running).fetch_add(1, Ordering::Relaxed);
    // The READ-BACK. `sched_on` has already halted if the model refused, so this is not error
    // handling — it is the difference between "EL2 asked for `Blocked`" and "the vCPU is `Blocked`",
    // which is the statement [`report_idle`] actually asserts.
    if hv.sched().state_of(slot_dom(cur), running.vcpu().model()) == Some(RunState::Blocked) {
        BLOCKED_READBACK_OK
            .of(running)
            .fetch_add(1, Ordering::Relaxed);
    }
    sched_on(
        hv,
        slot_dom(peer.guest()),
        scheduler_run(peer, now),
        "run the peer an idle vcpu yielded to",
    );
    drop(cell);
    WFI_YIELDS[cur].fetch_add(1, Ordering::Relaxed);
    switch_context(running.now_leaving(), peer, frame);
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
/// raising a software-generated interrupt. See [`hv_vdev::sgi`] for why the architecture routes it
/// here — an SGI names its targets by *physical* affinity, which a guest must not be allowed to
/// state — and for the decode of what it names. Everything else is reported with the decoded register
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
        // ★ This used to `park()` when the bank was full — a halt a guest could REACH, taking the
        //   peer domain with it. Delivery is now total: see `deliver_or_defer_vint` and
        //   `LINUX_PENDING`. There is no `false` left to branch on, which is what makes the halt
        //   unwritable rather than merely unwritten.
        //
        // ⑱-3b-i put the pending set on the **running vCPU**, because the list-register bank
        // `deliver_or_defer_vint` tries first is the running vCPU's — the set is where a vINT waits
        // for *that* bank to free a slot.
        //
        // ★★ ⑱-5 — **AND NOW THE OTHER AXIS: WHICH vCPU AN SGI IS AIMED AT.**
        //
        // Two rungs of comment here said this decode did not exist and named the reason it was safe
        // to skip. ⑱-3b-i's reason was "one vCPU per guest, so only one answer"; ⑱-3b-ii falsified
        // that and replaced it with a weaker, behavioural one — "only the boot vCPU is ever admitted,
        // so no sibling can be running to be targeted" — and said in as many words that it **expires
        // the moment ⑱-4 starts a second vCPU**. This is that rung, arriving first on purpose.
        //
        // The decode is `hv_vdev::sgi`, under the fence where `hv-verify` quantifies over the whole
        // 64-bit value a guest can write. What is left here is the part that needs the machine: which
        // pending set each named target's vINT goes into, and whether its bank is the live one.
        //
        // ⚠ **MEASURED, on a probe that was reverted.** Without this, a started second vCPU gives
        // `SMP: failed to stop secondary CPUs 1` on both guests and the boot gate TIMES OUT — every
        // IPI landing on whichever vCPU happened to be running. That measurement is why ⑱-5 goes
        // before ⑱-4 rather than after it, which is not the order the roadmap had.
        let running = current_vcpu();
        let slot = running.guest();
        let decoded = hv_vdev::sgi::decode(value, vcpu_affinity(running.vcpu().get()));
        let intid = decoded.intid();
        // ★★ ⑱-7 — **THIS GUARD IS THE WHOLE OF INTERRUPT CONFINEMENT BETWEEN GUESTS.**
        //
        // ⚠ **It used to read "Two independent reasons, and the loop is the stronger one" — and
        // there are NOT two.** The first was said to be the affinity comparison: a value naming a
        // peer's vCPU would still have to match. **It always matches.** `guest_mpidr` is
        // `MPIDR_RES1 | vcpu_affinity(vcpu)` and `vcpu_affinity` **takes no guest argument at all**,
        // so dom 1's vCPU 1 and dom 2's vCPU 1 have *identical* affinity. The collision is in the
        // function's SIGNATURE, not in its arithmetic — it cannot be fixed by choosing better
        // numbers, and no decode under the fence can ever distinguish two guests.
        //
        // ★★ **⑱-8 MADE IT A ROLE INSTEAD OF A GUARD.** ⑱-7 wrote the bound out as an explicit
        // `g != slot` comparison with a counter, so the mechanism was at least visible. But a
        // comparison is still something a future edit can drop, and this one had already been
        // dropped once in spirit — `PerVcpu::at`'s own doc records ⑱-5 reaching for the
        // arbitrary-index accessor because "an SGI names a target vCPU that is not the one running,
        // so its pending set is reachable through no role at all". The missing thing was a role for
        // a SIBLING, and `Running::own_vcpus` is it.
        //
        // There is no peer in this iteration, so there is nothing to compare and nothing to forget.
        // The hazard is still measured — see `note_affinity_collisions`, and note that a counter of
        // REFUSALS would now read zero and look fine.
        note_affinity_collisions(running, |aff| decoded.targets(aff));
        leak_to_peers_if_probing(running, |aff| decoded.targets(aff), intid);
        for own in running.own_vcpus() {
            let target = own.vcpu();
            if !decoded.targets(vcpu_affinity(target.get())) {
                continue;
            }
            if target == running.vcpu() {
                // The target is on the pCPU: its list registers are the live ones, so this is ③-a2's
                // path unchanged — inject, or defer into its own set and arm `UIE`.
                deliver_or_defer_vint(
                    LINUX_PENDING.of(running),
                    SGI_TARGETS_NAMED.at(slot),
                    SGIS_DELIVERED.at(slot),
                    SGIS_DEFERRED.at(slot),
                    intid,
                );
            } else if LINUX_PENDING.own(own).mark(intid) {
                SGI_TARGETS_NAMED.at(slot).fetch_add(1, Ordering::Relaxed);
                // ★ A SIBLING vCPU, which is the whole point of the rung. Its bank is NOT live, so
                //   there is nothing to inject into and `UIE` must NOT be armed — `UIE` is a
                //   statement about the running vCPU's list registers, and arming it here would make
                //   EL2 take a maintenance interrupt about a bank that is already empty (III-1's
                //   livelock, reached from the other side). The set is the whole delivery, and
                //   `flush_pending_to_lrs` drains it when that vCPU is switched IN.
                SGIS_ROUTED.at(slot).fetch_add(1, Ordering::Relaxed);
            }
        }
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
        current_vcpu(),
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
        // ★ A bare-metal slot gets its OWN assertion rather than a skip, and the distinction is the
        // point. `witness()`'s needle is a **Linux userspace** marker, so it can never fire for a
        // payload that has no userspace — asserting it here would fail a slot that is working, and
        // skipping the slot would drop the strongest piece of co-residency evidence this boot
        // produces. What is checkable for the monitor is the same mechanism minus the needle: the
        // emulator was entered and relayed the payload's bytes. That is ingress through a SECOND,
        // non-Linux tenant's device model, which nothing before this configuration could witness.
        if !runs_linux(slot) {
            if traps > 0 && dr_writes > 0 {
                let _ = writeln!(
                    uart,
                    "baleen: vpl011 OK: dom {dom}'s console is EMULATED — the bare-metal monitor's \
                     own bytes reached dom {dom}'s emulated PL011 DR in EL2 ({traps} register \
                     traps, {dr_writes} bytes relayed). The 'BALEEN-STEP0-OK' needle is NOT checked \
                     here and could not be: it is a Linux userspace marker and this partition has \
                     no userspace"
                );
            } else {
                let _ = writeln!(
                    uart,
                    "baleen: vpl011 FAIL: dom {dom}'s bare-metal payload transmitted nothing \
                     through its emulator ({traps} register traps, {dr_writes} bytes) — either it \
                     never ran or its console window is not being trapped"
                );
                crate::park();
            }
            continue;
        }
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
        // Five of this file's driver witnesses live in this one loop, so the payload exemption is
        // asked once here rather than five times below — five conditionals would be five chances to
        // word one differently or forget it entirely.
        if !linux_driver_witnesses_apply(slot, uart) {
            continue;
        }
        let dom = slot_dom(slot);
        let n = TIMER_FORWARDED.at(slot).load(Ordering::Relaxed);
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

        let (gic_traps, gic_enables) = VGIC.borrow_mut().at_mut(slot).witness();
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

        let switches = SWITCHES.at(slot).load(Ordering::Relaxed);
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

        let sgis = SGIS_DELIVERED.at(slot).load(Ordering::Relaxed);
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

        // ⑱-6 — the routed-SPI witness. Reported per guest beside `vsgi`, because the two are the
        // two halves of the same question: an SGI is routed by the register the guest writes to
        // *raise* it, an SPI by the register it writes to *aim* it.
        let named = SPI_TARGETS_NAMED.at(slot).load(Ordering::Relaxed);
        let routed = SPIS_ROUTED.at(slot).load(Ordering::Relaxed);
        let delivered = SPIS_DELIVERED.at(slot).load(Ordering::Relaxed);
        let deferred = SPIS_DEFERRED.at(slot).load(Ordering::Relaxed);
        let unroutable = SPIS_UNROUTABLE.at(slot).load(Ordering::Relaxed);
        // The same one-disposition identity `vsgi` asserts. It is a property of the mechanism, not
        // of the workload, so it holds whatever the guest did with its routing table.
        let accounted = named == delivered + deferred + routed;
        // ★ `delivered == 0` is an assertion, not an observation. The witness fires only from a vCPU
        // the route does NOT name, so the running-vCPU path is unreachable for it — a non-zero
        // `delivered` would mean the SPI went where the pCPU was rather than where the guest aimed
        // it, which is the pre-⑱-6 behaviour this rung removes.
        if routed > 0 && delivered == 0 && unroutable == 0 && accounted {
            let _ = writeln!(
                uart,
                "baleen: vspi OK: dom {dom} re-aimed INTID {WITNESS_SPI} away from its boot vCPU \
                 and EL2 HONOURED it — {routed} SPI(s) placed in a NON-RUNNING vCPU's pending set \
                 ({named} named = {delivered} delivered + {deferred} deferred + {routed} routed, \
                 {unroutable} unroutable), from GICD_IROUTER the guest wrote itself"
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: vspi FAIL: dom {dom} routed no SPI to a non-running vCPU \
                 ({named} named, {delivered} delivered, {deferred} deferred, {routed} routed, \
                 {unroutable} unroutable) — either the guest never re-aimed INTID {WITNESS_SPI}, or \
                 GICD_IROUTER is being recorded and ignored again"
            );
        }

        // ★★ ⑲ — the guest-reachable RETIREMENT SURFACE of this guest's distributor, counted.
        let (answered, refused) = VGIC.borrow_mut().at_mut(slot).survey_gicd();
        let (checked, all_zero) = VGIC.borrow_mut().at_mut(slot).banked_res0_read_zero();
        if all_zero && checked > 0 && answered > 0 && refused > 0 {
            let _ = writeln!(
                uart,
                "baleen: gicdsurface OK: of {} word offsets in dom {dom}'s GICD frame, {answered} \
                 are answered and {refused} RETIRE the guest — and all {checked} \
                 redistributor-banked RES0 copies read ZERO rather than retiring it, which before \
                 ⑲ they did not",
                answered + refused
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: gicdsurface FAIL: dom {dom} — {checked} banked RES0 copies checked, all \
                 zero = {all_zero}, {answered} answered, {refused} refused. A zero in `checked` or \
                 `refused` means the sweep collapsed and proves nothing; a false `all_zero` means a \
                 conforming guest can still be retired by a legal read"
            );
        }

        // ★★ ⑱-7 — the interrupt axis of ISOLATION, reported beside the two routing axes it guards.
        let collisions = AFFINITY_COLLISIONS.at(slot).load(Ordering::Relaxed);
        if collisions > 0 {
            let _ = writeln!(
                uart,
                "baleen: irqconfine OK: {collisions} interrupt target(s) named by dom {dom} ALSO \
                 described a PEER vCPU — vcpu_affinity() takes no guest argument, so the collision \
                 is real and continuous; ⑱-8 makes delivering to those vCPUs unrepresentable rather \
                 than refusing them, so this counts the HAZARD, not a guard firing"
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: irqconfine FAIL: dom {dom} never named an affinity a peer vCPU also has, \
                 so the hazard the role fence exists for did not occur even once — either the \
                 guests have stopped colliding (vcpu_affinity gained a guest argument?) or this \
                 guest raised no interrupts at all. Either way the confinement claim needs re-reading"
            );
        }
    }
}

// ─── ③-b2b-ii-b: what the loader actually deposited ──────────────────────────────────────────────

/// arm64 `Image` header, from `Documentation/arch/arm64/booting.rst`: `image_size` at +16, `flags`
/// at +24, and the `ARM\x64` magic at +56.
const IMAGE_SIZE_OFF: u64 = 16;
const IMAGE_FLAGS_OFF: u64 = 24;
pub(crate) const IMAGE_MAGIC_OFF: u64 = 56;
/// `"ARM\x64"` as the little-endian `u32` the header stores.
pub(crate) const IMAGE_MAGIC: u32 = 0x644d_5241;
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
        // A monitor slot has no externally loaded blobs at all — `crate::monitor::load` copies its
        // payload out of hv-metal's own `.rodata` and reports what it deposited. Checking for an
        // `Image` header here would fail on a window that is correct, so the slot is skipped BY NAME
        // rather than silently: a loop that quietly covers fewer slots than it iterates is the
        // subset-as-total defect, and this report is exactly where it would be invisible.
        if !runs_linux(slot) {
            let _ = writeln!(
                uart,
                "baleen: guestimage n/a: dom {} carries no loaded image — its payload is copied \
                 from EL2's .rodata, so there is no Image, DTB or initramfs to read back here \
                 (see the `monitor` line for what WAS deposited)",
                slot_dom(slot)
            );
            continue;
        }
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
        let released = HW_RELEASED.at(slot).load(Ordering::Relaxed);
        let deactivated = TIMER_DEACTIVATED.at(slot).load(Ordering::Relaxed);
        let handovers = HANDOVERS.at(slot).load(Ordering::Relaxed);

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
        // ★ **`released + deferred == deactivated`, and the `+ deferred` is this rung.**
        //
        // The old form was `released == deactivated`, and the comment above called it "the
        // load-bearing one, **unchanged**". It was — right up until a forwarded tick could be
        // DEFERRED. A deferred timer is Active with **no list register**, so the next handover
        // demotes nothing (`released += 0`) while the redistributor still confirms an
        // Active -> Inactive transition (`deactivated += 1`), and the old equality refuses a
        // perfectly correct boot.
        //
        // **That is the SIXTH time in this arc that an invariant mentioning a count turned out to be
        // a claim about the workload** — here, the claim that every Active physical timer had been
        // forwarded. It was true only while forwarding could not fail.
        //
        // The repair STRENGTHENS the cross-check rather than relaxing it: every controller-confirmed
        // deactivation is accounted for by exactly one of the two ways EL2 can stop owning that
        // line — it demoted a mapping it had made, or it never made one because the bank was full.
        // Deleting either term breaks the equality, which is what the witness is for.
        //
        // ─── ⑱-3b-i: RE-DERIVED FOR TWO vCPUs, AND THE ANSWER IS NOT THE ONE THE ARC EXPECTED ───
        //
        // ⑱-3a declared these two conjuncts unre-derived and made re-deriving them the FIRST task of
        // the next rung, on the grounds that an invariant naming a count had turned out to be a claim
        // about the workload six times already. Done, and **both survive** — for a reason worth
        // stating, because it is not the reason they were doubted:
        //
        //   `released` and `deactivated` are attributed by the SAME `cur`, in the same statement of
        //   `switch_context`; `deferred` is attributed at forward time to the vCPU that will be `cur`
        //   at the very next handover, because nothing else runs in between. So this is a
        //   **per-handover local identity**, and the per-guest counter is merely where the sum is
        //   kept. Summing a local identity over a guest's vCPUs preserves it.
        //
        // The seventh candidate was not a workload claim. **The defect is one level down, and it is
        // the argument `TIMER_FORWARDED` already makes about itself:** *"Per guest since
        // ③-b2b-ii-a. A merged count would stay green with one guest's forwarding path entirely
        // dead."* At two vCPUs **the per-guest counter IS the merged count**. A guest whose vCPU 1
        // handoff is entirely dead contributes `released = 0, deactivated = 0` to each of its own
        // handovers — which balances — so this witness stays GREEN with half the new tenant broken.
        //
        // ⚠ **DECLARED FOR ⑱-4, NOT CLOSED HERE, and the reason WAS that it is not yet checkable.**
        // At `VCPUS_PER_GUEST == 1` a `PerVcpu<AtomicU64, G, 1>` is `[[T; 1]; G]` — isomorphic to
        // the `[T; G]` it would replace, so moving the fifteen counters is behaviour-nil AND
        // witness-nil, and produces no build error either, because `AtomicU64` implements both
        // marker traits by `crate::role`'s declared convention. It becomes a real check the moment a
        // second vCPU produces counts, together with the kill probe that makes it one: kill vCPU 1's
        // release path alone, and the per-vCPU report must redden while the per-guest sum does not.
        //
        // ★ **THE PRECONDITION IS NOW MET AND THE ITEM IS STILL OPEN — say so rather than let the
        // paragraph above keep reading as "not yet".** ⑱-4b-ii starts a real second vCPU: this
        // guest's handovers are now shared between two of them, so these per-guest counters ARE the
        // merged count the paragraph warns about, and the kill probe it describes is finally
        // runnable. It is deliberately NOT done in this rung — moving fifteen counters is its own
        // change with its own probe — but it is now a deferral by choice rather than by
        // impossibility, which is a different claim and the honest one.
        //
        // ⚠ Note what ⑱-4b-ii DID move, because it is the same hazard: `seeded == admitted` in
        // [`report_vcpu_census`] is asserted PER GUEST, not on the sum, for exactly this reason.
        let deferred = TIMER_DEFERRED.at(slot).load(Ordering::Relaxed);
        let ok = released + deferred == deactivated && released <= handovers;
        if ok {
            let _ = writeln!(
                uart,
                "baleen: handoff OK: dom {dom} gave the forwarded timer up every time it left the \
                 pCPU holding one — {released} hardware-mapped list registers demoted and {} \
                 controller-confirmed Active -> Inactive transitions of PPI {}, across {handovers} \
                 handovers ({deferred} tick(s) deferred for a full bank and redelivered); then \
                 re-armed from the incoming guest's own emulated distributor",
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

/// ★ **⑱-4b-ii's witness: every vCPU the metal can name is one the MODEL knows, every secondary was
/// SEEDED before it was ADMITTED, and every one of them went down with its domain.**
///
/// ## What changed from ⑱-3b-ii, and it is a STRENGTHENING rather than a relaxation
///
/// That rung asserted `dispatched == 0` — *no vCPU but the boot one ever reached the pCPU* — which
/// was the correct claim while nothing could start one, and is **false by design** here. It is not
/// relaxed away; it is replaced by the two statements it was really standing in for, both of which
/// stay true for every rung after this:
///
/// * **`seeded == admitted`, PER GUEST** — EL2 never made a vCPU eligible to run that it had not
///   first given a context to. The dangerous thing was never "a non-boot vCPU"; it was an
///   **unseeded** one, which ⑱-3b-ii measured as `EC=0x20 ELR=FAR=0x0` and a boot that never
///   finished. The ordering inside [`cpu_on`] makes that inversion unreachable and
///   [`switch_context`]'s guard makes it loud if it ever became reachable again. Counted at the two
///   sites independently, so a path that admitted without seeding is a difference rather than
///   silence.
///
///   ⚠ **Asserted per guest and NOT on the sum**, which is the reason the counters are indexed at
///   all. `TIMER_FORWARDED`'s doc names the hazard: *"A merged count would stay green with one
///   guest's forwarding path entirely dead."* Here a global equality balances when dom 1 seeds one
///   and admits none while dom 2 admits one it never seeded — the two errors cancelling to hide
///   exactly the inversion the conjunct is for. The sums are still printed, because a reader wants
///   the total; the *assertion* is over each guest.
/// * **`nonboot_offline == nonboot`** — ⚠ **this conjunct was DELIBERATELY WEAK in ⑱-3b-ii, which
///   said so, and it is now the load-bearing one.** There it read "every non-boot vCPU is Offline"
///   at a point where nothing had ever started one, so it would have passed on a model in almost any
///   state. Here secondaries really run, and a domain that retires must take *all* of them down —
///   otherwise `next_runnable` keeps handing the pCPU to a retired domain's parked sibling while its
///   peer starves. This is the assertion that catches that, and it is FALSE on the code ⑱-3b-ii
///   shipped.
/// * **`known == TOTAL`** — unchanged: `hv-core` answered `Some(_)` for every `(guest, vCPU)` the
///   metal can name, i.e. metal and model agree about the size of the axis. What `main.rs`'s
///   `VCPUS_PER_DOMAIN >= VCPUS_PER_GUEST` assert pins at compile time, checked against the model
///   that was actually built.
/// * **`NONBOOT > 0`** — non-vacuity, and still honestly a **compile-time** quantity rather than
///   anything a guest produced. Kept because it costs nothing and stops the marker being satisfied
///   by a build that never raised the count.
///
/// ## What is REPORTED and never asserted
///
/// **The dispatch count is this rung's headline and is deliberately not asserted**, along with the
/// per-guest seeded/admitted/refused lines. They are claims about the workload: a guest that never
/// issues `CPU_ON` produces zero and that is a correct boot, and a guest may legitimately ask for a
/// CPU it already has. The mechanism's own statements are the four above. Design-lesson #127.
///
/// ## ★ THE GUEST-OBSERVED HALF LIVES IN THE MARKER LIST, and it is the stronger evidence
///
/// This function is EL2's account of itself. The kernels' account is
/// `SMP: Total of 2 processors activated.` — a required marker — and its twin
/// `SMP: Total of 1 processors activated.`, which is FORBIDDEN. The twin is what does the work:
/// `seeded == admitted` reads `0 == 0` on a build where `CPU_ON` silently never fires, and this
/// marker would stay green; the forbidden string appears the moment *either* guest fails to bring
/// its second CPU up. MEASURED as the exact baseline output before this rung existed.
///
/// ## Honest ceiling
///
/// `hv-metal` is not a Kani target. This is a boot witness over the live model, not a theorem. It
/// says a secondary was seeded, admitted and retired correctly; it does **not** say the secondary
/// executed the guest's code correctly — that is what the kernel's own SMP line and its clean
/// shutdown say instead.
fn report_vcpu_census(uart: &mut Pl011) {
    const TOTAL: usize = NUM_GUESTS * VCPUS_PER_GUEST;
    const NONBOOT: usize = NUM_GUESTS * (VCPUS_PER_GUEST - 1);

    let Some(mut cell) = crate::guest::GUEST_HV.try_borrow_mut() else {
        let _ = writeln!(
            uart,
            "baleen: vcpus FAIL: the model was borrowed at report time, so the vCPU census is \
             UNWITNESSED on this boot"
        );
        crate::park();
    };
    let Some(hv) = cell.as_mut() else {
        let _ = writeln!(uart, "baleen: vcpus FAIL: there is no model to census");
        crate::park();
    };

    let (mut known, mut nonboot, mut nonboot_offline) = (0usize, 0usize, 0usize);
    for (slot, vcpu) in crate::role::census(NUM_GUESTS) {
        let Some(state) = hv.sched().state_of(slot_dom(slot), vcpu.model()) else {
            continue;
        };
        known += 1;
        if !vcpu.is_boot() {
            nonboot += 1;
            if state == RunState::Offline {
                nonboot_offline += 1;
            }
        }
    }
    drop(cell);

    let dispatched = DISPATCHED_NONBOOT.load(Ordering::Relaxed);
    let sum = |c: &PerGuest<AtomicU64, NUM_GUESTS>| -> u64 {
        (0..NUM_GUESTS)
            .map(|s| c.at(s).load(Ordering::Relaxed))
            .sum()
    };
    let seeded = sum(&SECONDARIES_SEEDED);
    let admitted = sum(&SECONDARIES_ADMITTED);
    let refused = sum(&CPU_ON_REFUSED);
    // ⚠ **PER GUEST, not on the sum, and the difference is the whole point of the counters being
    // indexed.** `TIMER_FORWARDED`'s doc states the hazard exactly: *"A merged count would stay
    // green with one guest's forwarding path entirely dead."* A global `seeded == admitted` balances
    // when dom 1 seeds one and admits none while dom 2 admits one it never seeded — which is
    // precisely the inversion this conjunct exists to catch, cancelling itself out across guests.
    let seed_before_admit_everywhere = (0..NUM_GUESTS).all(|s| {
        SECONDARIES_SEEDED.at(s).load(Ordering::Relaxed)
            == SECONDARIES_ADMITTED.at(s).load(Ordering::Relaxed)
    });

    let ok = known == TOTAL
        && nonboot == NONBOOT
        && NONBOOT > 0
        && nonboot_offline == nonboot
        && seed_before_admit_everywhere;
    if ok {
        let _ = writeln!(
            uart,
            "baleen: vcpus OK: each of the {NUM_GUESTS} guests has {VCPUS_PER_GUEST} vCPUs and \
             hv-core knows all {known} of them — {admitted} secondary vCPU(s) started by PSCI \
             CPU_ON, every one of them SEEDED BEFORE IT WAS ADMITTED ({seeded} of {admitted}), \
             dispatched onto the pCPU {dispatched} time(s), and all {nonboot_offline} of the \
             {nonboot} non-boot vCPUs Offline again once their domain retired ({refused} CPU_ON \
             request(s) refused — reported, not asserted)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: vcpus FAIL: {known} of {TOTAL} (guest, vCPU) pairs known to the model, \
             {nonboot} of {NONBOOT} non-boot, {nonboot_offline} of those Offline at the end, and \
             {seeded} seeded against {admitted} admitted — either a vCPU was admitted without a \
             context, or a retired domain left one Runnable for the scheduler to keep picking"
        );
        crate::park();
    }
    for slot in 0..NUM_GUESTS {
        let _ = writeln!(
            uart,
            "baleen: vcpus: dom {} — {} secondary seeded, {} admitted, {} CPU_ON request(s) \
             refused (reported, never asserted: a guest that never calls CPU_ON produces zero, and \
             that is a correct boot)",
            slot_dom(slot),
            SECONDARIES_SEEDED.at(slot).load(Ordering::Relaxed),
            SECONDARIES_ADMITTED.at(slot).load(Ordering::Relaxed),
            CPU_ON_REFUSED.at(slot).load(Ordering::Relaxed)
        );
    }
}

/// ⑱-1 — **the identity a guest reads is one EL2 wrote.**
///
/// Structural, and deliberately so. The value is unchanged from what QEMU's reset already provided
/// (measured `0x80000000`/`0x410fd083` before this rung and after it), so **no guest behaviour can
/// witness this** — a count of "guests that booted" would have been just as green on `main`, which
/// is design-lesson #99's test. What is assertable is that the registers were *written by us* and
/// **read back as what we wrote**, on every entry to EL1 rather than on some of them. That is true
/// every boot, unsatisfiable by luck, and false on `main` — where the write does not exist.
///
/// The non-vacuity evidence is the kill probe recorded beside [`set_guest_identity`], which is
/// guest-observed and therefore stronger than anything this function can assert.
fn report_guest_identity(uart: &mut Pl011) {
    let writes = IDENTITY_WRITES.load(Ordering::Relaxed);
    let verified = IDENTITY_VERIFIED.load(Ordering::Relaxed);
    let vmpidr = IDENTITY_VMPIDR.load(Ordering::Relaxed);
    let vpidr = IDENTITY_VPIDR.load(Ordering::Relaxed);
    if writes > 0 && verified == writes {
        let _ = writeln!(
            uart,
            "baleen: identity OK: every entry to EL1 carries an identity EL2 CHOSE — VMPIDR_EL2 \
             read back as 0x{vmpidr:x} (the MPIDR_EL1 a guest reads, Aff0 = its own vCPU index) and \
             VPIDR_EL2 as 0x{vpidr:x} (MIDR_EL1, taken off the PE the guest really runs on), \
             {verified} of {writes} entries. Both are UNKNOWN at reset, so before this the guests' \
             identity was the implementation's choice and not the hypervisor's"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: identity FAIL: {verified} of {writes} entries read back the identity EL2 wrote \
             (VMPIDR_EL2 0x{vmpidr:x}, VPIDR_EL2 0x{vpidr:x}) — a guest is running with an identity \
             nothing chose"
        );
        crate::park();
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
/// ⚠ **⑱-4b-i CHANGED THE WORKLOAD BUT NOT THIS DECISION, and the distinction matters.**
/// `guest-init.sh` now sleeps for a second, so both guests DO reliably idle and these counts are no
/// longer the coin flip described above (six boots of the previous init: two trapped zero). That
/// makes a non-vacuity assertion defensible — and [`report_idle`] makes exactly one, over the
/// mechanism ⑱-4b-i added. It is deliberately NOT made here: this marker is about `HCR_EL2.TWI`
/// being in force, which is true whether or not any guest ever idles, and widening it to depend on
/// the init's sleep would couple a `③-b2b-ii-e`-era structural claim to a later rung's harness.
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

/// ★ **⑱-4b-i's witness: a vCPU that says it has nothing to do STOPS BEING A SCHEDULER CANDIDATE,
/// and comes back.**
///
/// ## The three conjuncts, and what each would catch
///
/// * **`blocked > 0` — non-vacuity, and it is enforced by the MARKER LIST, not by this function.**
///   `idle OK` is printed only when something was actually blocked, and it is a required marker of
///   the **shipped** configuration alone. A boot that exercises nothing prints `idle: NOT EXERCISED`
///   instead, which is not the required string, so the gate reddens on absence.
///
///   ⚠ **THIS WAS FIRST WRITTEN AS A PARK CONDITION HERE, AND THAT WAS WRONG — the fault
///   configuration MEASURED it wrong within the hour.** The reasoning was: idling used to be
///   incidental guest behaviour (six boots of the previous init gave (1,0) (0,0) (0,0) (1,1) (0,1)
///   (1,1) `wfi` traps, **two of them zero**), `guest-init.sh` now sleeps on purpose, therefore
///   idling is the HARNESS's behaviour and may be asserted. **The premise was true and the
///   conclusion did not follow.** Blocking needs a *peer*, not merely an idle vCPU — and the harness
///   also KILLS a guest in two of its three configurations. In the fault boot dom 2 idled 97 times,
///   found dom 1 already retired, took the [`wait_at_el2`] path every time and blocked **zero**
///   times. Perfectly correct, and the assertion parked EL2 and hung the boot to a 300 s timeout.
///
///   The lesson is the arc's most-repeated one arriving in a new disguise: *a count is a claim about
///   the workload*, and calling the workload "ours" does not change what the count depends on. What
///   is safely assertable here is the two identities below, which are vacuously true at zero.
///
/// * **`readback == blocked` — the structural one, and the one that cannot be satisfied by luck.**
///   Every `SchedBlock` this file issued was followed by asking the model what state that vCPU is
///   actually in, and getting `Blocked`. [`sched_on`] already halts on a *refused* transition, so
///   this is not error handling: it is the gap between "EL2 asked" and "the model agrees", which is
///   the gap `HCR_EL2`'s read-back in [`report_wfi_yield`] closes for a register.
///
/// * **`woken + retired_asleep == blocked` — conservation, and it is the LIVENESS half.** Every vCPU
///   this file put to sleep left `Blocked` by one of exactly two routes: it was woken, or its domain
///   retired and took it down asleep. A vCPU that left by neither is starved — its guest stops making
///   progress, never reaches `poweroff`, and before this conjunct existed the likeliest symptom was
///   a boot timing out with no explanation.
///
///   ⚠ **⑱-4b-i asserted the narrower `woken == blocked`, and was RIGHT TO — then this rung broke
///   it, and that is the identity working rather than failing.** At one vCPU per guest the retiring
///   vCPU is always the `Running` one, so no `Blocked` vCPU could be offlined and the second term was
///   provably zero; it was considered and deliberately left out. `CPU_ON` plus retire-all makes it
///   reachable, and the very first boot of this rung reported **290 blocked, 289 woken**. A witness
///   that survives a change to the machine unchanged has usually not been told anything.
///
/// * **`sweeps >= preempts` — the FAIRNESS one, and it exists because a probe FAILED to kill.**
///   Every preemption gave the blocked vCPUs a chance before choosing who runs next. `>=` and not
///   `==` because [`retire_and_hand_over`] sweeps too, at most once per guest per boot; the
///   inequality is the honest form and the excess is bounded by `NUM_GUESTS`.
///
///   [`WAKE_SWEEPS`] is counted INSIDE [`wake_blocked_vcpus`] and [`PREEMPTS`] outside it, on
///   purpose: a counter on the call site would be deleted along with the call, and the identity
///   would still balance. See probe A below for why that mattered.
///
/// ## What is REPORTED and never asserted
///
/// **The yield counts.** They are the rung's headline and they are the guests' behaviour, not the
/// mechanism's: `main` measured **8,735 per guest** for one second of idleness, every trap yielding,
/// the two counts identical to the unit. That is the ping-pong. What this rung leaves is bounded by
/// EL2's slice instead, so the number should collapse — but the *specific* number it collapses to is
/// a function of tick rates and scheduling luck, and asserting it would be refusing a correct boot
/// for being fast. Design-lesson #127.
///
/// ## ★ THE PROBES — there are two wake sites, and they FAIL DIFFERENTLY
///
/// | # | probe | predicted | measured |
/// |---|---|---|---|
/// | A | delete the sweep in [`preempt_through_the_scheduler`] | does not kill | **did not kill — gate fully GREEN.** Re-run after `sweeps >= preempts` was added: **kills**, at `2 sweeps against 218 preemptions` |
/// | B | delete the sweep in [`retire_and_hand_over`] | kills | **killed: `82 blocked, 81 woken`** (⑱-4b-i era, one vCPU per guest; the counts are larger now, the verdict is not) |
///
/// **Probe B**, the easy one: dom 1's last block is never woken, `end_of_boot` runs while its kernel
/// is still asleep, and the boot reddens. Worth noting *how* it was caught — **both**
/// `BALEEN-IDLE-END` markers still printed, because dom 1 had finished its sleep long before the
/// lost wake. The guest-observed marker saw nothing. The conservation identity caught it on a
/// difference of **one out of eighty-two**, which is the whole argument for having it.
///
/// **Probe A is the interesting one, and it is why `sweeps >= preempts` exists.** Deleting the
/// slice sweep left the gate GREEN. The retire path's own sweep still rescued the blocked vCPU at
/// teardown, so `woken == blocked` balanced — at **1 == 1**, because dom 1 blocked ONCE and then sat
/// `Blocked` for the entire boot (69 dispatches against dom 2's 151) instead of blocking 82 times
/// and being woken 82 times. A guest starved for a second, reported as a clean pass.
///
/// That is a latency and fairness defect rather than a correctness one, which is exactly why the
/// identity missed it: *the counts still balance when the mechanism barely runs*. `sweeps >=
/// preempts` is structural instead — it is about what EL2 did on every preemption, not about how
/// often the guests happened to idle — and it turns probe A from green into red.
///
/// ⚠ **Two further honesty notes.** First, every one of these probes was USELESS before
/// `guest-init.sh` gained its sleep: on a boot that traps zero `wfi`s, removing a waker changes
/// nothing, and a probe that fires on two boots in three is not a probe. That is why the sleep is
/// part of this rung rather than a convenience. Second, **the reverse probe — restoring
/// `SchedPreempt` — does NOT kill and cannot be made to**: the machine still works, just 122×
/// harder. It is caught by the *reported* counts and a human reading them, not by the gate, and
/// pretending otherwise would overstate this marker.
///
/// ## Honest ceiling
///
/// `hv-metal` is not a Kani target. This is a boot witness over the live model, not a theorem. It
/// says every vCPU that went idle was descheduled and re-offered; it says **nothing** about the wake
/// arriving when the guest's own deadline expires, which is honest-ledger item 9's open form and
/// which [`wake_blocked_vcpus`] openly substitutes a whole-slice sweep for.
///
/// ✅ **A CAVEAT THIS DOC DECLARED AND ⑱-4b-ii RETIRED — recorded because the retirement is the
/// interesting part.** At one vCPU per guest the conjuncts were sums that ONE GUEST LARGELY CARRIED:
/// two boots split 81 blocks as **81/0** and **80/1** between dom 1 and dom 2, because
/// [`handle_linux_wfi`]'s ask-first order meets the rotation — by the time dom 2 went idle dom 1 was
/// usually already `Blocked`, leaving dom 2 no peer to hand to and sending it down the untouched
/// [`wait_at_el2`] path. So `81 == 81 == 81` was evidence about one guest wearing the shape of
/// evidence about two.
///
/// **With a second vCPU per guest actually running it is gone, measured:** 465 blocks split
/// **117 / 194 / 109 / 45** across dom 1 vcpu 0/1 and dom 2 vcpu 0/1 — every vCPU carrying a real
/// share. What fixed it was not this rung: more runnable vCPUs mean a yielding one usually *does*
/// find a peer, so the ask-first path stops funnelling into `wait_at_el2`. The per-vCPU lines below
/// the marker are printed precisely so a split like the old one stays visible instead of hiding
/// inside the sum.
fn report_idle(uart: &mut Pl011) {
    let sum = |c: &PerVcpu<AtomicU64, NUM_GUESTS, VCPUS_PER_GUEST>| -> u64 {
        crate::role::census(NUM_GUESTS)
            .map(|(g, v)| c.at(g, v).load(Ordering::Relaxed))
            .sum()
    };
    let blocked = sum(&VCPUS_BLOCKED);
    let readback = sum(&BLOCKED_READBACK_OK);
    let woken = sum(&VCPUS_WOKEN);
    let retired_asleep = sum(&VCPUS_OFFLINED_WHILE_BLOCKED);
    let sweeps = WAKE_SWEEPS.load(Ordering::Relaxed);
    let preempts = PREEMPTS.load(Ordering::Relaxed);

    // ★ THE IDENTITIES ARE THE PARK CONDITION; NON-VACUITY IS NOT. Both are vacuously true at
    //   `blocked == 0`, and that is the correct answer for a boot in which no vCPU ever had a peer
    //   to yield to — see the doc above for the fault-configuration measurement that taught this.
    if readback != blocked || woken + retired_asleep != blocked || sweeps < preempts {
        let _ = writeln!(
            uart,
            "baleen: idle FAIL: {blocked} vCPU block(s), {readback} of them read back as Blocked, \
             {woken} woken again and {retired_asleep} retired while still asleep, and {sweeps} wake \
             sweep(s) against {preempts} preemption(s) — either a vCPU EL2 blocked is NOT Blocked \
             in the model, or one left Blocked by neither route (a starved guest), or a preemption \
             chose a vCPU without first giving the blocked ones a chance"
        );
        crate::park();
    }
    if blocked > 0 {
        let _ = writeln!(
            uart,
            "baleen: idle OK: a vCPU that executed WFI left the scheduler's candidate set and came \
             back — {blocked} block(s), all {readback} of them read back as Blocked from the model \
             itself, and every one accounted for on the way out ({woken} woken, {retired_asleep} \
             retired with their domain). An idle peer is no longer handed the pCPU it just gave up"
        );
    } else {
        // Neither OK nor FAIL, and deliberately neither: the identities above hold, but nothing
        // exercised them. Saying so in its own words is what stops a reader — or a marker list —
        // reading a vacuous pass as a witness.
        let _ = writeln!(
            uart,
            "baleen: idle: NOT EXERCISED — no vCPU ever executed WFI with a peer available to take \
             the pCPU, so none was blocked and this boot witnesses nothing about the mechanism. \
             Expected whenever a guest has been retired and the survivor idles alone. The shipped \
             configuration requires 'idle OK', so seeing THIS line there would redden the gate"
        );
    }
    for (slot, v) in crate::role::census(NUM_GUESTS) {
        let b = VCPUS_BLOCKED.at(slot, v).load(Ordering::Relaxed);
        if b == 0 {
            continue;
        }
        let _ = writeln!(
            uart,
            "baleen: idle: dom {} vcpu {} — blocked {b} time(s), woken {} (reported, never \
             asserted — a workload number; see report_idle's docs for what it replaced)",
            slot_dom(slot),
            v.get(),
            VCPUS_WOKEN.at(slot, v).load(Ordering::Relaxed)
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
/// ★ **⑱-4a's witness: a vCPU resumes on its OWN virtual active priorities.**
///
/// ## What this closes, and it was found by measurement rather than by reading the ARM ARM
///
/// `ICH_AP0R<n>_EL2`/`ICH_AP1R<n>_EL2` hold the priorities a vCPU has acknowledged and not yet
/// ended. While a bit is set the virtual CPU interface signals nothing at or below that priority —
/// so they are per-vCPU state in exactly the sense the list registers and `ICH_VMCR_EL2` are, and
/// they were the one member of that class [`gic::VgicCtx`] did not carry. A vCPU preempted between
/// `ICC_IAR1_EL1` and its EOI left its bit behind for whoever was restored next, **across vCPUs and
/// across DOMAINS**, since one physical interface serves both guests.
///
/// The measurement is on [`AP_FOREIGN`]. In one line: with a second vCPU per guest the boot
/// deadlocks permanently, `ICH_AP1R0_EL2` stuck at `0x10000`.
///
/// ## The conjunct that is asserted, and the one that is not
///
/// * **`verified == switches`** — asserted. Every switch-in reads the interface back and finds the
///   incoming vCPU's own priorities. Structural: true on every boot, unsatisfiable by a lucky
///   workload, and false the moment a restore is dropped.
/// * **`foreign`** — reported. Whether a switch lands inside a handler is the workload's business:
///   measured **0, 0, 1, 1 per guest across four consecutive boots** of the shipped configuration.
///   The condition is real here and it is also a coin toss, which is exactly the shape of thing
///   that must not be a gate in either direction (design-lesson #127).
///
/// ## What the assertion cannot see, and the poison that can
///
/// A read-back proves the restore is faithful; on the two boots in four where nothing is left
/// behind it cannot by itself prove the guest *depends* on it. That half is the **poison**
/// ([`gic::VgicCtx::poison_live`]): every priority is set active between save and restore, so a
/// dropped restore is fatal rather than invisible. The pair is the point — the read-back watches
/// the mechanism, the poison makes it load-bearing.
///
/// ## ★ THE PROBES, and the rig's own control row
///
/// | # | probe | observed |
/// |---|---|---|
/// | **CONTROL** | restore the two groups in the opposite order — behaviour-nil | **clean boot, witness green.** The rig discriminates rather than defaulting to "survived" (design-lesson #180) |
/// | **P1** | delete the RESTORE; keep save and poison | ★ **KILLED, reproduced twice.** Both kernels reach userspace and print `poweroff`; neither ever issues `PSCI SYSTEM_OFF`; the gate reddens on the missing markers |
/// | **P2** | delete the SAVE; keep restore and poison | **SURVIVED, witness green** — the declared ceiling above, stated because it was measured and not because it was predicted |
/// | **P3** | delete the `apr` field | **KILLED AT BUILD: three `E0026`s, one per destructuring** (save, restore, poison), plus one `E0609` from the accessor. This is the class fix working |
/// | **P4** | delete the AP poison; keep save and restore | **SURVIVED** — behaviour-nil on this workload, which is exactly why the poison is there for the workload where it is not |
/// | **P5** | write `u64::MAX` to `ICH_AP0R0_EL2` and read it straight back | **`0xffffffff`** — QEMU honours the write, so P4's poison is real and P1's kill is not an artefact of an ignored register |
/// | **P6** | ★ the payoff. On ⑱-4b's configuration (`cpu@1`, two vCPUs per guest), remove save, restore and poison — i.e. put `VgicCtx` back to exactly what `main` carries | **KILLED: the original stall, reproduced.** One guest boots and powers off, the survivor never finishes. With the pair present the whole `qemu-linux-test` — three boot configurations — is GREEN on that branch |
///
/// P6 is the row that matters and it is deliberately last: it is the only one measured against the
/// workload this rung exists for, and it was run against the SHIPPED code rather than the scoping
/// prototype, because "the prototype fixed it" and "this diff fixes it" are two different claims.
///
/// ⚠ **P3's FIRST version was a build error for the WRONG REASON** — it deleted the field and left
/// its doc comment, so `E0585` (a doc comment documenting nothing) fired before any destructuring
/// could. Design-lesson #172, caught only by reading the compiler output instead of the exit code.
/// The row above is the corrected probe.
///
/// ⚠ **And the rig ate the rung once.** Its revert step was `git checkout -- hv-metal/src` while the
/// work was still uncommitted, which restored `main`. Commit before running a destructive rig; the
/// revert target must be the rung, not its parent.
///
/// ## Honest ceiling
///
/// `hv-metal` is not a Kani target, so this is a boot witness, not a theorem. The read-back compares
/// the interface against the **stored** context, so it witnesses the restore and not the save —
/// deleting the save alone leaves it green (probe P2). And the register list is an **enumeration**
/// of the writable per-vCPU `ICH_*` state (`LR`, `VMCR`, `AP0R`, `AP1R`; `HCR` is EL2's and
/// recomputed per switch-in; `VTR`/`EISR`/`ELRSR`/`MISR` are read-only) — the same kind of audit
/// that undercounted once before (design-lesson #155). Say "enumerated", not "complete".
fn report_active_priorities(uart: &mut Pl011) {
    for slot in 0..NUM_GUESTS {
        // No `witnesses_assertable` guard, deliberately, and matching [`report_fp_isolation`]
        // beside it: `verified == switches` is not a count that a retired domain leaves
        // legitimately short — both sides increment in the same statement of `switch_context`, so
        // a domain that made three switches and died has three of three. The guard exists for
        // reports whose zero is honest on a faulted boot; this one has no such zero.
        let dom = slot_dom(slot);
        let verified = AP_RESTORE_VERIFIED.at(slot).load(Ordering::Relaxed);
        let switches = SWITCHES.at(slot).load(Ordering::Relaxed);
        let foreign = AP_FOREIGN.at(slot).load(Ordering::Relaxed);
        if verified == switches {
            let _ = writeln!(
                uart,
                "baleen: vapr OK: dom {dom} resumed on its OWN virtual active priorities every \
                 time — {verified} of {switches} switch-ins read ICH_AP0R/ICH_AP1R back off the \
                 interface equal to the context restored, and on {foreign} of them the interface \
                 had been left holding a priority the PREVIOUS vCPU had acknowledged and not ended \
                 (that count is the workload's, not the mechanism's)"
            );
        } else {
            let _ = writeln!(
                uart,
                "baleen: vapr FAIL: dom {dom} verified {verified} active-priority restores across \
                 {switches} switch-ins — the interface does not hold what EL2 restored, so a vCPU \
                 is running under a priority its peer acknowledged and its own interrupts are being \
                 vetoed"
            );
            crate::park();
        }
    }
}

fn report_fp_isolation(uart: &mut Pl011) {
    for slot in 0..NUM_GUESTS {
        let dom = slot_dom(slot);
        let verified = FP_RESTORE_VERIFIED.at(slot).load(Ordering::Relaxed);
        let switches = SWITCHES.at(slot).load(Ordering::Relaxed);
        let foreign = FP_FOREIGN.at(slot).load(Ordering::Relaxed);
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
        let (gic_traps, gic_enables) = vgic.at(slot).witness();
        let (_, pl011_traps, dr_writes) = pl011[slot].witness();
        [
            gic_traps,
            gic_enables,
            pl011_traps,
            dr_writes,
            console.lines(slot),
            TIMER_FORWARDED.at(slot).load(Ordering::Relaxed),
            SGIS_DELIVERED.at(slot).load(Ordering::Relaxed),
            SWITCHES.at(slot).load(Ordering::Relaxed),
            HANDOVERS.at(slot).load(Ordering::Relaxed),
            MAX_HOLD[slot].load(Ordering::Relaxed),
            PEER_FAULTS.at(slot).load(Ordering::Relaxed),
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
        // The same reasoning one axis over, and the same requirement to say so out loud: five of
        // these eleven counters tally KERNEL DRIVER traffic (GIC traps, INTID enables, forwarded
        // ticks, SGIs, refused peer accesses), which a partition with no drivers correctly leaves at
        // zero. ★ Its counters are still PRINTED below, and that is deliberate — the ones it does
        // exercise (its own PL011 traps, console bytes and lines, dispatches, handovers) are
        // non-zero beside dom 1's, which is exactly the not-shared evidence this report exists for.
        // What is dropped is the parking, not the evidence.
        if !runs_linux(slot) {
            let _ = writeln!(
                uart,
                "baleen: perguest: dom {} carries the bare-metal monitor payload — its counters are \
                 PRINTED below but not asserted, because five of the eleven tally kernel driver \
                 traffic a partition with no drivers correctly never generates",
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
                // ⚠ The count is [`NUM_LINUX`], not `NUM_GUESTS`: a slot whose counters were exempted
                // above must not be claimed as one they were asserted for. With no payload swap
                // compiled in the two are equal and this line is byte-identical to what it always
                // was — which is why the shipped corpus's marker is unchanged.
                "baleen: perguest OK: the guests' device models, vCPU contexts and witnesses are \
                 INDEXED, not shared — all {} of them are non-zero for EVERY one of the \
                 {NUM_LINUX} guests, which no arrangement of shared state produces (a shared \
                 model carries both guests' work in one tally and leaves the other at zero){}",
                PER_GUEST_COUNTERS.len(),
                if NUM_MONITOR == 0 {
                    ""
                } else {
                    ". The bare-metal slot's own tallies are printed below and are non-zero where \
                     it has a mechanism to exercise, which is the same not-shared evidence"
                }
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
    // ⚠ **Counted, never written down.** This line used to say `{NUM_GUESTS} REAL … kernels`, which
    // was one hardcoded relationship — "every slot runs Linux" — asserted in the first sentence of
    // the transcript. The `monitor` configuration makes it false, and a number that only a human
    // re-reads is a number that rots (design-lesson #276). Both counts are now derived from
    // [`payload_of`], so the banner cannot disagree with what the boot actually seeds.
    let _ = writeln!(
        uart,
        "baleen: M5 Arc 5e — booting {NUM_LINUX} REAL aarch64 Linux kernel(s) + {NUM_MONITOR} \
         bare-metal monitor partition(s) as EL1 guests time-slicing ONE pCPU (dom {GUEST_A} owns \
         0x{GUEST_RAM_BASE:08x}..0x{split:08x}, dom {GUEST_B} owns \
         0x{split:08x}..0x{GUEST_RAM_END:08x})",
        split = stage2::LINUX_RAM_SPLIT
    );

    // The monitor's payload has no external loader, so EL2 deposits it here — BEFORE
    // `report_loaded_images`, which is the readback of what every slot now holds. Doing the copy
    // first is what lets that report speak about all `NUM_GUESTS` slots in one pass instead of
    // being silent about one of them.
    #[cfg(feature = "monitor")]
    crate::monitor::load(
        uart,
        MONITOR_SLOT,
        guest_ram_base(MONITOR_SLOT),
        PARTITION.window_len,
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
        VTTBR.at(slot).store(*v, Ordering::Relaxed);
    }

    // ★★ ⑲-2 — **BIND A REAL BUS MASTER TO A REAL GUEST'S OWN Stage-2 IMAGE.**
    //
    // Here and not earlier: the images must EXIST, and `VTTBR` must hold them, before a device can
    // be pointed at one. Here and not later: nothing is executing yet, so writing the positive
    // control's sentinel into dom 1's RAM cannot disturb a running kernel.
    //
    // ⚠ **This rung is CONFINEMENT, not SIMULTANEITY** — nothing runs while THIS device DMAs. What
    // it changes is WHOSE map confines it: a real guest's proven image rather than apparatus built
    // for the test. Honest-ledger item 2(b) is closed a few lines below by ⑲-3b, which arms a second
    // transfer that is deliberately still in flight when the `eret` happens.
    //
    // ⑲-3a: both targets are now the guests' **reserved landing pads**. They used to be
    // `guest_ram_base(slot) + 0x0800_0000` — a hand-picked address chosen for being above the blobs,
    // which is exactly the guess the pad exists to retire, and which was only safe because nothing
    // was running. Note that the helper SEEDS the forbidden address too, so the peer's target must
    // be a page the peer does not mind losing; before the pad, that was an ordinary page of dom 2's
    // RAM and the safety argument rested entirely on the timing.
    #[cfg(feature = "smmu")]
    crate::dmawitness::witness_real_guest(
        uart,
        vttbr[SLOT_A],
        vttbr[1],
        dma_pad_ipa(SLOT_A),
        dma_pad_ipa(1),
    );

    // ★ ⑲-3a — seed each guest's reserved landing pad, and do it LAST.
    //
    // After `VTTBR` holds both images, because the seed goes through each guest's own Stage-2 walk;
    // after ⑲-2, because that witness transfers INTO these same pads and leaves its own values in
    // them; and before the first `eret`, because the whole claim is that what a guest finds there is
    // what EL2 put there. Any EL2 write to a pad added below this line silently turns the power-off
    // check into a check of that write instead.
    seed_dma_pads(uart);

    // ★★ ㉑ — TWO BUS MASTERS, at the quiesced moment. Leaves both devices released, so ⑲-3b's arm
    // below finds the machine it expects.
    #[cfg(feature = "smmu")]
    crate::dmawitness::witness_two_masters(
        uart,
        hv,
        slot_dom(SLOT_A),
        slot_dom(1),
        vttbr[SLOT_A],
        vttbr[1],
        dma_pad_ipa(SLOT_A) + 0x2000,
        dma_pad_ipa(1) + 0x2000,
    );

    // ★★ ⑲-3b — ARM the in-flight observation. One `DeviceAssign` through the proven dispatch; the
    // kick itself waits until the guests have been running for `FLIGHT_KICK_AFTER` exits.
    //
    // The targets are the SECOND page of each guest's reserved pad. The base holds ⑲-3a's sentinel
    // and `report_dma_pad` still checks it, so the two witnesses share the pad without sharing an
    // address.
    #[cfg(feature = "smmu")]
    {
        let l1_peer = hv_s2::arm64::vttbr_table(vttbr[1]);
        match crate::dmawitness::inflight_arm(
            uart,
            hv,
            slot_dom(SLOT_A),
            vttbr[SLOT_A],
            l1_peer,
            dma_pad_ipa(SLOT_A) + 0x1000,
            dma_pad_ipa(1) + 0x1000,
        ) {
            Some(f) => {
                flight::BAR0.store(f.bar0, Ordering::Relaxed);
                flight::SID.store(u64::from(f.sid), Ordering::Relaxed);
                flight::OWN_IPA.store(f.own_ipa, Ordering::Relaxed);
                flight::OWN_PA.store(f.own_pa, Ordering::Relaxed);
                flight::PEER_IPA.store(f.peer_ipa, Ordering::Relaxed);
                flight::PEER_PA.store(f.peer_pa, Ordering::Relaxed);
                flight::PHASE.store(1, Ordering::Relaxed);
            }
            None => crate::park(),
        }
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
    // ★ ⑱-3b-ii — **ONLY THE BOOT vCPU IS ADMITTED, and this line is the rung's safety boundary.**
    //
    // `VCPUS_PER_GUEST` is 2, so every guest now HAS a second vCPU: the model allocated it, the
    // emulated GIC gives it a redistributor, and `next_runnable` offers it on every rotation. What it
    // does not have is a context — `VcpuCtx::new()` is zeroed — so dispatching it would `eret` to
    // PC = 0 and fault at the guest's first instruction.
    //
    // Nothing here forbids that. `hv-core` boots every vCPU `Offline` and `SchedAdmit` is the only
    // way out of that state; not calling it leaves the model answering `Offline`, and
    // `next_runnable`'s `== Some(Runnable)` is what turns that answer into a refusal. **So the guard
    // is a proven state machine's run state, not a range check or a flag this file keeps** — which is
    // why the second vCPU can exist a whole rung before anything can start it.
    //
    // ⑱-4 admits it, and must seed the context FIRST: `CPU_ON` carries the entry point in `x2`.
    for slot in 0..NUM_GUESTS {
        sched_on(
            hv,
            slot_dom(slot),
            HvCall::SchedAdmit {
                vcpu: VcpuIdx::boot().model(),
            },
            "admit a linux vcpu",
        );
    }
    sched_on(
        hv,
        GUEST_A,
        scheduler_run(Incoming::at(SLOT_A, VcpuIdx::boot()), now),
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
    // ⑱-1 — guest A is the one vCPU that reaches EL1 by an `eret` rather than by a context restore,
    // so it needs the identity installed here too. Same function, not a second answer.
    //
    // ⑱-3b-i: spelled as an ARRIVAL, because that is what it is — guest A's boot vCPU is about to
    // come onto the pCPU, and `set_guest_identity` now says so in its type. This is the one place
    // `VcpuIdx::boot()` is the honest answer on this path rather than the constant that was there
    // because there was only one.
    set_guest_identity(Incoming::at(SLOT_A, VcpuIdx::boot()));
    // ⑱-4b-ii — **guest A's boot vCPU IS seeded, and it is the one that never calls `seed_boot`.**
    // Its context is established by the `eret` below — `ELR_EL2`/`SPSR_EL2` written directly — so it
    // is entered rather than restored-from-zero, and [`switch_context`]'s guard has to know that.
    // Marking it here rather than exempting the boot vCPU from the check is the difference between a
    // guard with one hole in it and a guard with none.
    VCPU_SEEDED
        .at(SLOT_A, VcpuIdx::boot())
        .store(1, Ordering::Relaxed);

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
    // ⑱-4b-ii — the one moment `SCTLR_EL1` holds the value a guest BOOTS with, so this is where a
    // secondary's copy has to be taken from. See [`SCTLR_AT_BOOT`].
    SCTLR_AT_BOOT.store(sctlr_at_boot, Ordering::Relaxed);
    {
        let mut ctx = VCPU_CTX.borrow_mut();
        for slot in (0..NUM_GUESTS).filter(|&s| s != SLOT_A) {
            // ⑱-3b-i: `VcpuIdx::boot()` and not "the running vCPU" — a guest's FIRST switch-in is
            // by definition onto the vCPU it boots on. ⑱-4b-ii adds the third seeding site, for a
            // vCPU a guest asks for by `PSCI CPU_ON`, and that one is not this answer.
            VCPU_SEEDED
                .at(slot, VcpuIdx::boot())
                .store(1, Ordering::Relaxed);
            // ★ The payload swap in one value. A bare-metal tenant is entered at the same window
            // base under the same `SPSR`/`SCTLR_EL1` — it is an EL1 guest booting on a machine with
            // the MMU off, which is what the arm64 boot protocol describes and is not a Linux fact.
            // What differs is `x0`: a kernel takes a DTB pointer there, and the monitor takes
            // nothing, so it is handed a zero rather than a pointer to a device tree describing a
            // machine it will never parse.
            let x0 = if runs_linux(slot) { dtb_addr(slot) } else { 0 };
            ctx.at_mut(slot, VcpuIdx::boot()).seed_boot(
                kernel_entry(slot),
                x0,
                SPSR_EL2_LINUX,
                sctlr_at_boot,
            );
            let _ = writeln!(
                uart,
                "baleen: dom {} seeded for its first switch-in — entry 0x{:08x}, x0 = {} \
                 0x{x0:08x}, SPSR 0x{SPSR_EL2_LINUX:x}, SCTLR_EL1 0x{sctlr_at_boot:x} (MMU off, as \
                 the arm64 boot protocol requires); it is entered by a context restore, not an eret",
                slot_dom(slot),
                kernel_entry(slot),
                if runs_linux(slot) { "DTB" } else { "(none)" },
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
