// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # `hv-metal` — the bare-metal layer (Arc 0)
//!
//! The southbound metal layer beneath the proven `hv-core` brain. **Arc 0** is the enabling step
//! of M3 (see `docs/ROADMAP.md`): a bare-metal AArch64 binary that boots on the QEMU `virt`
//! machine, prints a marker over the PL011 UART, and parks — establishing the dev + CI boot-test
//! loop that every later metal arc rides on. No hypervisor logic yet: EL2 setup is Arc 2, the
//! guest is M4.
//!
//! This is the one crate that carries `unsafe` (the workspace forbids it everywhere else). Here
//! `unsafe` is only raw MMIO to a fixed device address that exists on the `virt` machine; each use
//! is justified against the `hv-hal` fence the proofs assume.

#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::ptr;

// The entry point. QEMU (`-kernel`, `virt`, `virtualization=on`) starts us at EL2 with the MMU
// off. Set the stack, zero `.bss`, and hand off to Rust; if `rust_main` ever returns, park.
global_asm!(
    r#"
    .section .text.boot
    .global _start
_start:
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
    // Fallthrough / return: park.
2:  wfe
    b       2b
"#
);

/// PL011 UART data register on the QEMU `virt` machine (writing a byte transmits it).
const UART0_DR: *mut u8 = 0x0900_0000 as *mut u8;

/// Transmit one byte over the PL011.
///
/// # Safety
/// `UART0_DR` is the fixed MMIO address of the PL011 data register on the `virt` machine, which is
/// always mapped. Arc 0 runs with the MMU off, identity-mapped, so the raw write is valid.
fn uart_put(byte: u8) {
    // SAFETY: fixed, always-present device register on `virt`; see the fn docs.
    unsafe { ptr::write_volatile(UART0_DR, byte) };
}

/// Transmit a string over the PL011 (LF is left as-is; QEMU's console handles it).
fn uart_str(s: &str) {
    for b in s.bytes() {
        uart_put(b);
    }
}

/// Park the core low-power. Arc 0 has nothing to do once the marker is out.
fn park() -> ! {
    loop {
        // SAFETY: `wfe` is an unprivileged hint with no memory effect.
        unsafe { core::arch::asm!("wfe") };
    }
}

/// The Rust entry, called from `_start`. Prints the boot marker the CI boot-test asserts on, then
/// parks. The marker string is the contract with `hv-metal/boot-test.sh`.
#[no_mangle]
pub extern "C" fn rust_main() -> ! {
    uart_str("baleen: hv-metal alive (arc0)\n");
    park();
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    uart_str("baleen: PANIC\n");
    park();
}
