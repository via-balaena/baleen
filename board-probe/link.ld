/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Copyright (c) 2026 Via Balaena */

/*
 * ⚠ THE LOAD ADDRESS IS ONE OF THE TWO FACTS YOU MUST SUPPLY BEFORE THIS PROBE CAN RUN.
 * The other is the UART base (`src/main.rs`'s `UART0_BASE`).
 *
 * Default is QEMU `virt`'s DRAM base + 512 KiB, matching `hv-metal/linker.ld` — so the probe
 * SELF-TESTS on a platform whose answers are already known before it is trusted on one whose
 * answers are not. That ordering is the point: an instrument that has never been run where you
 * can check it is not an instrument.
 *
 * Typical alternatives, to be CONFIRMED from the board's own documentation rather than from here:
 *   QEMU virt          0x4008_0000   (this default)
 *   Raspberry Pi       0x0008_0000   (the historical kernel load address)
 * Anything else: read the vendor's boot documentation. Guessing produces a silent hang, because
 * nothing has initialised a UART yet at the point a wrong address bites.
 */
ENTRY(_start)
SECTIONS
{
  . = 0x40080000;
  .text   : { KEEP(*(.text.boot)) *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }
  .data   : { *(.data .data.*) }
  .bss    : { __bss_start = .; *(.bss .bss.* COMMON) __bss_end = .; }
  . = ALIGN(16);
  . += 0x10000;
  __stack_top = .;
}
