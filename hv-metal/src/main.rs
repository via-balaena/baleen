// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # `hv-metal` — the bare-metal layer (Arc 1)
//!
//! The southbound metal layer beneath the proven `hv-core` brain. Arc 0 stood up the dev + CI
//! boot-test loop; **Arc 1** (see `docs/ROADMAP.md`) turns its raw one-byte UART poke into a
//! *proper* [`pl011`] console — initialized, flow-controlled, and `write!`-able — the diagnostic
//! substrate every later metal arc reports through (exception decode, the `CurrentEL` readout,
//! `hv-core` dispatch results). Still no hypervisor logic: EL2 setup is Arc 2, the guest is M4.
//!
//! This is the one crate that carries `unsafe` (the workspace forbids it everywhere else). Here
//! `unsafe` is only volatile MMIO to fixed device addresses that exist on the `virt` machine; each
//! use is justified against the `hv-hal` fence the proofs assume (see [`pl011`] for the console's
//! contract and its `unsafe` accounting).

#![no_std]
#![no_main]

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
fn uart() -> Pl011 {
    // SAFETY: fixed, always-present PL011 base on `virt`; see the fn docs and `pl011`'s contract.
    unsafe { Pl011::new(UART0_BASE) }
}

/// Park the core low-power. Arc 1 has nothing to do once the banner is out.
fn park() -> ! {
    loop {
        // SAFETY: `wfe` is an unprivileged hint with no memory effect.
        unsafe { core::arch::asm!("wfe") };
    }
}

/// The Rust entry, called from `_start`. Brings up the PL011 console and prints the boot banner
/// the CI boot-test asserts on, then parks. The `hv-metal alive` substring is the contract with
/// `hv-metal/boot-test.sh`.
#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    let mut uart = uart();
    uart.init();
    // `writeln!` cannot fail here — `Pl011`'s `write_str` is infallible — so the result is ignored.
    let _ = writeln!(uart, "baleen: hv-metal alive (arc1) — PL011 console up");
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
