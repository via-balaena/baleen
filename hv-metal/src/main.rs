// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # `hv-metal` — the bare-metal layer (Arc 2)
//!
//! The southbound metal layer beneath the proven `hv-core` brain. Arc 0 stood up the dev + CI
//! boot-test loop; Arc 1 turned the raw UART poke into a *proper* [`pl011`] console; **Arc 2**
//! (see `docs/ROADMAP.md`) confirms we are at EL2, installs the [`exceptions`] vector table
//! (`VBAR_EL2`), and stands up a default handler that **decodes and reports** any synchronous fault
//! through that console instead of triple-faulting into a silent reset loop — *a fault becomes
//! diagnosable*. Still no hypervisor logic: linking `hv-core` is Arc 3, the guest is M4.
//!
//! This is the one crate that carries `unsafe` (the workspace forbids it everywhere else). Here
//! `unsafe` is volatile MMIO to fixed device addresses and EL2 system-register/vector setup — each
//! use is justified against the `hv-hal` fence the proofs assume (see [`pl011`] and [`exceptions`]
//! for the per-layer contracts and their `unsafe` accounting).

#![no_std]
#![no_main]

mod exceptions;
mod pl011;

use core::arch::global_asm;
use core::fmt::Write;
use core::panic::PanicInfo;

use pl011::Pl011;

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
/// exception vectors, then (optionally) proves they catch a fault before parking.
///
/// The `hv-metal alive` substring and the `CurrentEL = EL2` line are the contract with
/// `hv-metal/boot-test.sh`; the `--features selftest` build additionally emits the caught-exception
/// decode the boot-test asserts on (`EC=0x3c`).
#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    let mut uart = uart();
    uart.init();
    // `writeln!` cannot fail here — `Pl011`'s `write_str` is infallible — so the result is ignored.
    let _ = writeln!(
        uart,
        "baleen: hv-metal alive (arc2) — EL2 + exception vectors"
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
    //     vectors to garbage and triple-faults into a silent reset loop.
    exceptions::install_vectors();
    let _ = writeln!(uart, "baleen: VBAR_EL2 installed — exception vectors live");

    // (3) The diamond move: prove the vectors actually catch + decode a fault. Gated behind the
    //     `selftest` feature (off by default) so the default boot path stays clean for Arc 3 to
    //     build on, while CI still exercises the fault-catch on every arc (design-lesson #23).
    #[cfg(feature = "selftest")]
    {
        let _ = writeln!(uart, "baleen: exception self-test — executing BRK #0");
        // SAFETY: `BRK` is a software breakpoint; it deterministically raises a synchronous
        // exception taken to the current EL (EL2), which the installed handler catches + reports.
        unsafe { core::arch::asm!("brk #0") };
        // The handler halts and never returns here; reaching this line would be a real bug.
        let _ = writeln!(uart, "baleen: BUG — returned from the BRK self-test");
    }

    park();
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // A fresh console handle: the panic path must not depend on any prior state. On `virt` the
    // PL011 is usable from reset, so this reports even if we fault before `rust_main`'s `init`.
    let mut uart = uart();
    let _ = writeln!(uart, "baleen: PANIC: {info}");
    park();
}
