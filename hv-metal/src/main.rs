// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # `hv-metal` — the bare-metal layer (M5 Arc 1)
//!
//! The southbound metal layer beneath the proven `hv-core` brain. Arc 0 stood up the dev + CI
//! boot-test loop; Arc 1 turned the raw UART poke into a *proper* [`pl011`] console; Arc 2 confirmed
//! EL2 and installed the [`exceptions`] vector table so a fault becomes diagnosable; Arc 3 ran the
//! proven brain on the bare CPU (still pre-guest); **Arc 4** (see `docs/ROADMAP.md`) is where the
//! proof first touches a **guest**. The boot:
//!
//! 1. configures `HCR_EL2` for AArch64 EL2 operation ([`el2`]);
//! 2. realizes [`hv_hal::TimeSource`] on the ARM generic timer ([`time`]) — the first piece of the
//!    `hv-hal` fence to gain a real hardware backing (Architecture Audit #1);
//! 3. supplies a `#[global_allocator]` ([`heap`]) and links [`hv_core`], constructs a real
//!    `Hypervisor`, and dispatches a synthetic `HvCall` *directly* on the metal (Arc 3, kept as a
//!    regression);
//! 4. enters a trivial **EL1 guest** ([`guest`]) behind a minimal Stage-2: the guest issues `HVC`,
//!    the CPU traps to EL2, the saved registers are decoded through `hv-core`'s ABI seam and routed
//!    through the **actual `Hypervisor::dispatch`**, the result is handed back, and the guest
//!    observes it — trap-and-service, the first time the ∀-N brain serves a real guest.
//!
//! Arc 4 *refines* the proof (the model's dispatch, driven for a real guest on emulated hardware)
//! and is QEMU-sound for the functional round trip. It carries **no isolation content** — the
//! Stage-2 map is just enough to run the guest; the faithful `p2m`→Stage-2 refinement and the
//! negative-isolation test are Arc 5 (`docs/ROADMAP.md`, `docs/QEMU-AND-METAL.md`).
//!
//! This is the one crate that carries `unsafe` (the workspace forbids it everywhere else); `hv-core`
//! and `hv-hal`, linked here, keep building under their own `unsafe_code = "forbid"` manifests, so
//! the fence is not pierced. Here `unsafe` is volatile MMIO to fixed device addresses, EL2
//! system-register/vector setup, and the bump allocator — each use justified against the `hv-hal`
//! fence the proofs assume (see each module for its per-layer contract and `unsafe` accounting).

#![no_std]
#![no_main]
// NOTE (⑭): there was a CRATE-WIDE `#![cfg_attr(feature = "real-linux", allow(dead_code))]` here,
// justified as "the synthetic `guest` phases are replaced wholesale by `linux::run`, so its functions
// are legitimately unused in that build; the default/`selftest` builds (the ones CI lints) still
// exercise every one." That is true of `guest.rs` — and false of `linux.rs`, which is
// `#[cfg(feature = "real-linux")]`. The allow fired in the ONLY configuration that compiles
// `linux.rs`, making it the one module in this crate that NO build linted for dead code. Ten dead
// constants accumulated there under a comment asserting they had been removed.
//
// So the allow is now a SINGLE one, on `guest::run` — the one entry point `linux::run` displaces.
// `allow(dead_code)` marks an item as a live root for reachability, so allowing the root silences
// exactly the subtree under it: measured, dead code elsewhere in `guest.rs` is still caught, and
// `linux.rs` is linted like every other module. A blanket allow is a lint gate whose inputs cannot
// discriminate (design-lesson #71); allowing the root says "this entry point is displaced", which is
// the true statement.

mod abort;
mod blk;
mod cell;
#[cfg(feature = "real-linux")]
mod console;
mod ctx;
mod dmawitness;
mod el2;
mod exceptions;
mod fp;
mod gic;
mod guest;
mod heap;
#[cfg(feature = "real-linux")]
mod linux;
mod pcie;
mod pending;
mod pl011;
#[cfg(feature = "real-linux")]
mod role;
#[cfg(feature = "smmu")]
mod smmu;
mod stage2;
mod teardown;
mod time;
#[cfg(feature = "real-linux")]
mod vcpu;
#[cfg(feature = "real-linux")]
mod vgic;
mod virtio;
#[cfg(feature = "real-linux")]
mod vpl011;

use core::arch::global_asm;
use core::fmt::Write;
use core::panic::PanicInfo;

use hv_core::{HvCall, HvOutcome, Hypervisor};

use pl011::Pl011;
use time::GenericTimer;

// The entry point. QEMU (`-kernel`, `virt`, `virtualization=on`) starts us at EL2 with the MMU
// off. Park every CPU but the primary, then set the stack, zero `.bss`, and hand off to Rust; if
// `rust_main` ever returns, park.
global_asm!(
    r#"
    .section .text.boot
    .global _start
_start:
    // Only the primary CPU proceeds. The boot CPU has all-zero affinity; any secondary that
    // reaches here must not claim the single boot stack. On QEMU `virt` secondaries stay
    // PSCI-parked so today only the primary runs this, but the gate keeps the single-stack boot
    // sound before we bring APs online (or meet a non-PSCI / real-hardware reset). Mask
    // Aff2:Aff1:Aff0 (not just Aff0) so a secondary whose index lands in a higher affinity level
    // is still caught.
    mrs     x0, mpidr_el1
    and     x0, x0, #0xffffff
    cbnz    x0, 2f
    // Stack.
    ldr     x0, =__stack_top
    mov     sp, x0
    // Zero .bss (16-byte aligned, size a multiple of 16 by the linker script).
    ldr     x0, =__bss_start
    ldr     x1, =__bss_end
0:  cmp     x0, x1
    b.hs    1f
    stp     xzr, xzr, [x0], #16
    b       0b
1:  bl      rust_main
    // Secondary-park target, and the fallthrough if `rust_main` (`-> !`) ever returns.
2:  wfe
    b       2b
"#
);

/// Base of the PL011 UART on the QEMU `virt` machine.
///
/// `pub(crate)` since ③-a1: the real-Linux guest's PL011 is **emulated** at this same address
/// (`vpl011`), and that module compile-time-asserts the two agree — the guest is offered the
/// device `guest.dts` already names, so the DTB needed no edit.
pub(crate) const UART0_BASE: usize = 0x0900_0000;

/// Construct a handle to the `virt` PL011.
///
/// # Safety
/// `UART0_BASE` is the fixed MMIO base of the PL011 on the `virt` machine, always mapped; Arc 0/1
/// run identity-mapped with the MMU off. This is the sole precondition [`Pl011::new`] requires.
pub(crate) fn uart() -> Pl011 {
    // SAFETY: fixed, always-present PL011 base on `virt`; see the fn docs and `pl011`'s contract.
    unsafe { Pl011::new(UART0_BASE) }
}

/// Park the core low-power. Nothing runs after the banner (or after a caught fault is reported).
pub(crate) fn park() -> ! {
    // ③-b2b-ii-a: the real-Linux guests' console is LINE-buffered in EL2 now, so a guest that dies
    // mid-line leaves its last fragment held rather than on the wire — and that fragment is exactly
    // the sort of thing a fatal path is being diagnosed from. Flushing here rather than at each of
    // the ten `park()` sites in `linux.rs` keeps it one derivation and covers the ones a future rung
    // adds. It appears *after* the trap message that named the fault, which is the one cost.
    //
    // `try_borrow_mut` inside: `park()` is also what `crate::cell`'s own conflict halt calls, and a
    // halt caused by the console cell must not re-enter it.
    #[cfg(feature = "real-linux")]
    linux::flush_consoles();
    loop {
        // SAFETY: `wfe` is an unprivileged hint with no memory effect.
        unsafe { core::arch::asm!("wfe") };
    }
}

/// The Rust entry, called from `_start`. Brings up the console, confirms EL2, installs the
/// exception vectors, configures `HCR_EL2`, realizes the generic-timer `TimeSource`, then links the
/// proven brain and dispatches a synthetic `HvCall` on the metal — before (optionally) self-testing
/// and parking.
///
/// The `hv-metal alive` substring and the `CurrentEL = EL2` line are the contract with
/// `hv-metal/boot-test.sh`, as are the Arc-3 markers (`HCR_EL2.RW=1`, `generic timer live`, the
/// dispatch result). The `--features selftest` build additionally asserts the `HvCall` accounting
/// witness and then exercises the Arc-2 fault-catch (`EC=0x3c`).
#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    let mut uart = uart();
    uart.init();
    // `writeln!` cannot fail here — `Pl011`'s `write_str` is infallible — so the result is ignored.
    let _ = writeln!(
        uart,
        "baleen: hv-metal alive (arc3) — the proven brain runs on the metal"
    );

    // (1) Confirm we are actually at EL2 before trusting any EL2 system register — a real check,
    //     not an assumption. QEMU `virt` with `virtualization=on` boots us at EL2.
    let el = exceptions::current_el();
    if el == 2 {
        let _ = writeln!(
            uart,
            "baleen: CurrentEL = EL2 (running at the hypervisor level)"
        );
    } else {
        let _ = writeln!(uart, "baleen: CurrentEL = EL{el} — expected EL2; halting");
        park();
    }

    // (2) Install the exception vectors. Until VBAR_EL2 points at a real table, any fault at EL2
    //     vectors to garbage and triple-faults into a silent reset loop. Read VBAR_EL2 back and gate
    //     the marker on it — so the *default* boot (which fires no fault) still witnesses the install
    //     took, not merely that the call returned.
    let (vbar_intended, vbar_readback) = exceptions::install_vectors();
    if exceptions::vbar_installed(vbar_intended, vbar_readback) {
        let _ = writeln!(
            uart,
            "baleen: VBAR_EL2 installed — exception vectors live (VBAR=0x{vbar_readback:016x})"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: VBAR_EL2 install FAILED (intended=0x{vbar_intended:016x} readback=0x{vbar_readback:016x}); halting"
        );
        park();
    }

    // ③-b2b-ii-f: clear `CPTR_EL2.TFP` so EL2 may touch the FP register file at all — it cannot
    //     carry a guest's `v0..v31` across a switch otherwise. Its reset value is UNKNOWN, exactly
    //     like `HCR_EL2`'s below, so it is written explicitly and read back rather than inherited.
    let cptr = fp::enable_at_el2();
    let _ = writeln!(
        uart,
        "baleen: EL2 owns the FP register file: CPTR_EL2 read back as 0x{cptr:x} (TFP clear = {})",
        fp::el2_fp_enabled(cptr)
    );

    // (3) Configure HCR_EL2 for AArch64 EL2 operation (RW=1, everything else 0 — no guest-trap
    //     bits, that is M4). Read it back and confirm the field took; a silent no-op write is a bug.
    let hcr = el2::configure();
    if el2::rw_is_aarch64(hcr) {
        let _ = writeln!(
            uart,
            "baleen: HCR_EL2.RW=1 (EL1=AArch64) — value=0x{hcr:016x}"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: HCR_EL2 write did not take (0x{hcr:016x}); halting"
        );
        park();
    }

    // (3a) Report `SCTLR_EL2` — the MMU-off baseline the EL2-MMU arc (ledger item 5) must preserve.
    //
    // ⚠ Reported, not asserted, and deliberately so. This crate cites "EL2 runs MMU-off" as a
    // premise in ~50 places, but MMU-off is not one behaviour: `M == 0` fixes DATA accesses at
    // Device-nGnRnE, while INSTRUCTION accesses follow `SCTLR_EL2.I`. An identity mapping that
    // changes "nothing but permissions" therefore has to match whatever `I` actually is here — and
    // nobody had read it. Every other platform fact this project checked this week turned out to
    // differ from the assumption it carried, so this one gets measured before code depends on it.
    let sctlr = el2::sctlr_el2();
    let _ = writeln!(
        uart,
        "baleen: SCTLR_EL2=0x{sctlr:016x} M={} C={} I={}",
        u8::from(sctlr & el2::SCTLR_EL2_M != 0),
        u8::from(sctlr & el2::SCTLR_EL2_C != 0),
        u8::from(sctlr & el2::SCTLR_EL2_I != 0),
    );

    // (4) Realize hv_hal::TimeSource on the ARM generic timer and witness that the count is
    //     monotonic and live (advances, is not frozen at zero) — the fence honored on the metal.
    let timer = GenericTimer;
    let freq = time::frequency();
    let adv = time::witness_advance(&timer, 1_000_000);
    if adv.monotonic && adv.advanced {
        let _ = writeln!(
            uart,
            "baleen: generic timer live: CNTFRQ={freq} Hz, CNTPCT {} -> {} (monotonic)",
            adv.start, adv.end
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: generic timer FAULT: monotonic={} advanced={} ({}->{}); halting",
            adv.monotonic, adv.advanced, adv.start, adv.end
        );
        park();
    }

    // (5) The Arc-3 headline: link the proven brain, construct a real Hypervisor, and dispatch a
    //     synthetic HvCall *directly* on the bare CPU (no guest). Kept as the Arc-3 regression:
    //     constructing the Hypervisor also exercises the #[global_allocator], a free witness that
    //     allocation works on the metal.
    dispatch_synthetic_hvcall(&mut uart);

    // (6) The Arc-3 accounting self-test (direct dispatch path), gated behind `selftest` and run
    //     *before* the guest because it returns cleanly; a witness produced by the dispatch itself
    //     (design-lesson #24(f)). The Arc-2 BRK fault-catch that used to follow it now runs at the
    //     end of the guest round-trip (chained inside `guest`'s terminal report handler under
    //     `selftest`), so every prior witness still fires in the same boot.
    #[cfg(feature = "selftest")]
    selftest_hvcall_accounting(&mut uart);

    // (6b) M5 Arc 4 — the concurrency predicate's non-vacuity witness. The nine `unsafe impl Sync`
    //      that used to rest on a commented "single boot CPU" are now one checked cell type; this
    //      asserts the check actually excludes (a second borrow refused while one is live, accepted
    //      once it drops) on both a probe cell and the live `GUEST_HV`. Runs before any guest, so no
    //      cell is claimed. A degenerate flag — always-set or never-set — fails one half or the other.
    #[cfg(feature = "selftest")]
    cell::selftest_exclusion(&mut uart);

    // (6c) M5 Arc 7a — invariant I1's non-vacuity witness. Realizing `VcpuOps::inject_interrupt`
    //      makes an asynchronous EL2 injector possible; I1 (a `BootCell` is claimed only with IRQ
    //      masked) is what keeps that async agent from ever overlapping a live borrow. This asserts
    //      the IRQ-mask check discriminates (masked accepted, unmasked rejected) and that the live
    //      EL2 claim context is masked. The unmasked half is a synthetic value — never a real IRQ.
    #[cfg(feature = "selftest")]
    cell::selftest_irq_masked(&mut uart);

    // (6d) M5 Arc 7c — per-vCPU vGIC LR-ownership witness. A pending virtual interrupt lives in
    //      `ICH_LR0_EL2`, per-vCPU state the hardware does not swap; the context switch now carries it
    //      (`GuestContext::ich_lr0`). This asserts a switched-in vCPU does NOT inherit the peer's
    //      pending vINT and its own survives the round trip — closing the same class of latent leak the
    //      FP-register scope note names. Enables only the LR sysreg interface (no IMO); clears LR0 after.
    #[cfg(feature = "selftest")]
    guest::selftest_vgic_lr_ownership(&mut uart);

    // (6e) III-1 — the >N-pending overflow witness, and the retirement of the last correctness residue
    //      in the ledger. Arc 8b (6d above) made a FULL list-register bank *reported* rather than
    //      silently clobbering a pending vINT — and `inject_interrupt` then HALTED on that report. This
    //      asserts the replacement: a per-vCPU software pending set absorbs the overflow, the underflow
    //      maintenance interrupt is armed only while something waits for it, a refill drains the set into
    //      the bank in order, and a peer vCPU's refill takes NONE of it (the isolation half — a single
    //      global queue would reopen the cross-vCPU leak 8b/III-3 closed for the hardware half). The
    //      metal's live interrupt sources cannot fill 4 LRs, so the overflow is manufactured here.
    #[cfg(feature = "selftest")]
    guest::selftest_vgic_pending_overflow(&mut uart);

    // (6f) SMMU rung 1 — the DMA default-deny witness, and the FIRST statement baleen makes about bus
    //      masters. Every isolation result so far is about CPU accesses; a DMA-capable device ignores
    //      `VTTBR_EL2` entirely, so on real hardware it could write anywhere. `SMMU_GBPA`'s reset value
    //      leaves `ABORT` clear — i.e. BYPASS — so from power-on until the hypervisor configures the
    //      SMMU every device may DMA freely. This closes that window (`GBPA.ABORT`) BEFORE enabling any
    //      device's bus mastering, then proves it with a real bus master (QEMU's `edu`): its DMA over a
    //      sentinel is aborted. On a machine with no SMMU the same code is the POSITIVE CONTROL — the
    //      DMA must LAND, without which the abort result would be vacuous (design-lesson #66).
    //
    //      RUNG 2 follows in the same boot: a linear stream table covering every StreamID on PCIe
    //      bus 0, every entry zeroed (`STE.V = 0` = deny), installed BEFORE `CR0.SMMUEN` so no
    //      instant exists in which a bus master is admitted — the ∀-StreamID default-deny, proven
    //      over the builder in `hv-verify::smmu_stream_table` and witnessed here in five phases that
    //      differ only in one 64-byte entry. The FIRST of them is the through-STE positive control
    //      (bind the device's own StreamID to a bypass entry; the DMA must LAND), because an
    //      ∀-StreamID deny is satisfied trivially by a device that never reaches the table at all.
    //
    //      RUNG 3 follows it in the same boot: the device is bound to a DOMAIN — `STE.Config = 0b110`
    //      with `S2TTB` at the very Stage-2 tables `build_stage2_from_p2m` emitted for that domain
    //      from the proven `p2m`, under its VMID — so for the first time the hypervisor constrains
    //      WHERE a permitted device may write. One proven `p2m`, two consumers. Its control is
    //      stronger than rung 2's and again comes first: the DMA must land at the address the TABLE
    //      names and NOT at the address the device asked for, both read back. Then confinement (an
    //      IPA the domain does not own faults), permission (the emitter's read-only leaf refuses the
    //      DEVICE's write), and the binding itself (the same device, the same address, an STE naming
    //      the other domain, reaches nothing of the first domain's).
    dmawitness::witness(&mut uart);

    // (7) The guest headline: enter a real EL1 guest behind real Stage-2 emitted from the proven
    //     `p2m`, run the Arc-5 authorize/deny isolation matrix (the proof touches reality), then the
    //     M5 Arc 0 LIFECYCLE phase — destroy the guest and reborn a fresh domain in the same slot,
    //     witnessing that it inherits nothing (the confused-deputy defense) — then the M5 Arc 1
    //     SCHEDULER phase: two vCPUs time-slice under hv-core's real scheduler, each context
    //     preserved across the switch, exclusivity + affinity enforced. Terminal: the last phase's
    //     report handler parks (and, under `selftest`, chains the Arc-2 fault-catch first), so this
    //     never returns.
    //
    //     Under `--features real-linux` (M5 Arc 5e), the synthetic phases are replaced by the
    //     real-Linux capstone: `linux::run` boots an actual aarch64 Linux kernel as a single EL1
    //     guest that owns the machine (device pass-through, `IMO=0`). Feature-gated, so the default
    //     build — the one the CI boot-test asserts on — is unchanged.
    #[cfg(feature = "real-linux")]
    linux::run(&mut uart);
    #[cfg(not(feature = "real-linux"))]
    guest::run(&mut uart);
}

/// Parameters of the bring-up `Hypervisor`. Deliberately tiny — dom0 (slot 0) boots `Live` with a
/// credit account, which is all the synthetic call needs; the rest are `Dead` shells. Small enough
/// that the whole thing fits comfortably in the bump heap (see [`heap`]).
const NUM_DOMAINS: usize = 4;
const PORTS_PER_DOMAIN: usize = 4;
const GRANTS_PER_DOMAIN: usize = 4;
const VCPUS_PER_DOMAIN: usize = 2;
const NUM_PCPUS: usize = 2;

// ─── ⑱-3b-ii: the MODEL must have room for every vCPU the METAL can name ─────────────────────────
//
// **This was an unpinned relationship, and it had already drifted.** Three constants say how many
// vCPUs exist — `VCPUS_PER_DOMAIN` here (what the model allocates), `guest::NUM_VCPUS_METAL` (what
// the synthetic path time-slices) and `role::VCPUS_PER_GUEST` (what a real-Linux guest has) — and
// until this rung *nothing checked any of them against another*. `VCPUS_PER_DOMAIN` appeared in
// exactly two places: its definition and its single use.
//
// ⚠ **An INEQUALITY, not an equality, and the distinction is the honest part.** These are not three
// derivations of one fact (which #74 would say to collapse into one): the model's array is shared by
// both paths and must be big enough for whichever is compiled, while each metal path's count is its
// own statement about its own workload. What *is* a defect is the metal naming a vCPU the model does
// not have — `state_of` would answer `None`, `next_runnable` would silently never pick it, and a
// dispatch would be refused by a model that is right. So the checkable relationship is "big enough".
const _: () = assert!(
    VCPUS_PER_DOMAIN >= guest::NUM_VCPUS_METAL,
    "the model must have room for every vCPU the synthetic path time-slices"
);
#[cfg(feature = "real-linux")]
const _: () = assert!(
    VCPUS_PER_DOMAIN >= role::VCPUS_PER_GUEST,
    "the model must have room for every vCPU a real-Linux guest has — raising role::VCPUS_PER_GUEST \
     past VCPUS_PER_DOMAIN would make hv-core answer None for a vCPU the metal can name"
);

/// DMA-capable devices in the model — the SMMU arc's rung-4 assignment axis.
///
/// **The model's device population must match the MACHINE's**, which is why this is per-config
/// rather than one number: modelling devices that do not exist would put unassignable tokens in the
/// relation the stream table is derived from. `NUM_FRAMES` below is split for the same reason.
/// Every device boots **unassigned**, which the derivation refines to a *denying* stream-table entry
/// — so the model's fail-closed default and the hardware's are the same default, not two that happen
/// to agree. Both values sit under `hv_s2::smmu::MAX_PROVEN_DEVICES`, asserted in `smmu.rs`.
///
/// **㉑ — TWO on the real-Linux machine**, at PCIe slots 1 and 2 ⇒ StreamIDs 8 and 16, because that
/// is the only configuration with two real domains to assign them to. One device can show that
/// *permission* is per-stream (rung 2 phase 3, a permissive entry at a neighbouring StreamID);
/// showing that *translation* is per-stream needs two requesters walking two different Stage-2
/// images at once, and that is what the second one is for.
#[cfg(feature = "real-linux")]
pub(crate) const NUM_DEVICES: usize = 2;
/// One, because the synthetic SMMU machine has exactly one `edu` (PCIe slot 1 ⇒ StreamID 8).
#[cfg(not(feature = "real-linux"))]
pub(crate) const NUM_DEVICES: usize = 1;
/// Machine frames in the model. `pub(crate)` so [`guest`]'s per-frame fault-record array can
/// compile-time-assert it covers every model frame (see `guest::NFRAMES`).
#[cfg(not(feature = "real-linux"))]
pub(crate) const NUM_FRAMES: usize = 8;

/// The real-Linux guest's model: one frame per 2 MiB of its RAM, plus the `L2` page-table frames
/// those leaves hang off.
///
/// **Why more than one table.** `hv_core::TABLE_SLOTS` is **8** — a deliberate model abstraction
/// ("small enough that the `links` table stays bounded"), not a hardware fact. So one model table
/// holds at most 8 leaves and a real address space needs many of them; the metal composes them,
/// which is the refinement doing its job rather than a workaround. The emitted table does not
/// reflect the model's table *structure* at all — the refinement is over the LEAF SET (Audit #2's
/// leaf-level reachability scope), so 56 eight-leaf tables and one 448-leaf table would emit the
/// same Stage-2.
///
/// Every frame below `stage2::NUM_SUP_FRAMES` is a super-span frame (the metal's span partition);
/// the table frames sit just above it, in the base partition, and are never mapped — a page table is
/// model state, not a leaf.
#[cfg(feature = "real-linux")]
pub(crate) const NUM_FRAMES: usize =
    stage2::NUM_SUP_FRAMES as usize + stage2::NUM_LINUX_TABLES as usize;

/// Domain 0 — the primordial control domain, `Live` from boot with a credit account. The acting
/// domain for the synthetic call.
const DOM0: hv_core::hypervisor::DomId = 0;

/// Build a real `Hypervisor` sized by the constants above. `pub(crate)` so the Arc-4 guest module
/// ([`guest`]) can construct the brain the trap-and-service loop services.
pub(crate) fn build_hypervisor() -> Hypervisor {
    Hypervisor::new(
        NUM_DOMAINS,
        PORTS_PER_DOMAIN,
        GRANTS_PER_DOMAIN,
        VCPUS_PER_DOMAIN,
        NUM_PCPUS,
        NUM_FRAMES,
        NUM_DEVICES,
    )
}

/// Dispatch one synthetic `HvCall` — `dom0` grants itself 100 credits — through the real
/// `hv-core` dispatch path, and report the result. This is *the brain running on the metal*: the
/// call traverses `Hypervisor::dispatch` → `route` → the liveness gate → the credit subsystem,
/// exactly as it does on the host, and returns a value we check rather than merely print.
///
/// `CreditGrant` is the most minimal call that still runs the full path: dom0 is already `Live` with
/// a credit account, so there is zero setup, yet the outcome is a deterministic witness
/// (`grant 100 → Balance(100)`).
fn dispatch_synthetic_hvcall(uart: &mut Pl011) {
    let mut hv = build_hypervisor();
    match crate::teardown::dispatch(&mut hv, DOM0, HvCall::CreditGrant { amount: 100 }) {
        Ok(HvOutcome::Balance(100)) => {
            let _ = writeln!(
                uart,
                "baleen: HvCall CreditGrant(100) -> balance=100 (hv-core serviced it on the metal)"
            );
        }
        other => {
            // Any other outcome is a real bug in the linked brain or the dispatch plumbing.
            let _ = writeln!(uart, "baleen: HvCall UNEXPECTED outcome: {other:?}");
        }
    }
}

/// The Arc-3 self-test: assert the linked brain does real accounting across two calls — a witness
/// produced *by* the dispatch mechanism, kept as a permanent CI assertion (design-lesson #24(f)).
///
/// `grant 100` then `spend 30` must settle at `balance = 70`; the "accounting OK" marker is printed
/// **only** when both outcomes match exactly, so the boot-test matching it is genuine evidence the
/// dispatch returned the right values, not merely that it ran.
#[cfg(feature = "selftest")]
fn selftest_hvcall_accounting(uart: &mut Pl011) {
    let mut hv = build_hypervisor();
    let granted = crate::teardown::dispatch(&mut hv, DOM0, HvCall::CreditGrant { amount: 100 });
    let spent = crate::teardown::dispatch(&mut hv, DOM0, HvCall::CreditSpend { amount: 30 });
    if granted == Ok(HvOutcome::Balance(100)) && spent == Ok(HvOutcome::Balance(70)) {
        let _ = writeln!(
            uart,
            "baleen: selftest: HvCall accounting OK (grant 100, spend 30 -> balance 70)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: selftest: HvCall accounting FAIL (grant={granted:?} spend={spent:?})"
        );
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // A fresh console handle: the panic path must not depend on any prior state. On `virt` the
    // PL011 is usable from reset, so this reports even if we fault before `rust_main`'s `init`.
    let mut uart = uart();
    let _ = writeln!(uart, "baleen: PANIC: {info}");
    park();
}
