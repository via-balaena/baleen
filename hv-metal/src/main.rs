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

mod el2;
mod exceptions;
mod guest;
mod heap;
mod pl011;
mod stage2;
mod time;
mod virtio;

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
const UART0_BASE: usize = 0x0900_0000;

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

    // (7) The guest headline: enter a real EL1 guest behind real Stage-2 emitted from the proven
    //     `p2m`, run the Arc-5 authorize/deny isolation matrix (the proof touches reality), then the
    //     M5 Arc 0 LIFECYCLE phase — destroy the guest and reborn a fresh domain in the same slot,
    //     witnessing that it inherits nothing (the confused-deputy defense) — then the M5 Arc 1
    //     SCHEDULER phase: two vCPUs time-slice under hv-core's real scheduler, each context
    //     preserved across the switch, exclusivity + affinity enforced. Terminal: the last phase's
    //     report handler parks (and, under `selftest`, chains the Arc-2 fault-catch first), so this
    //     never returns.
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
/// Machine frames in the model. `pub(crate)` so [`guest`]'s per-frame fault-record array can
/// compile-time-assert it covers every model frame (see `guest::NFRAMES`).
pub(crate) const NUM_FRAMES: usize = 8;

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
    match hv.dispatch(DOM0, HvCall::CreditGrant { amount: 100 }) {
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
    let granted = hv.dispatch(DOM0, HvCall::CreditGrant { amount: 100 });
    let spent = hv.dispatch(DOM0, HvCall::CreditSpend { amount: 30 });
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
