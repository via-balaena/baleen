/* SPDX-License-Identifier: Apache-2.0 OR MIT */
/* Copyright (c) 2026 Via Balaena */

/*
 * Minimal linker script for the QEMU `virt` AArch64 machine.
 *
 * `virt` places RAM at 0x4000_0000; QEMU's `-kernel <elf>` loader honors the ELF program
 * headers and jumps to the entry point. We load the image a little above the RAM base and give
 * it a small stack. Everything is one contiguous image — no MMU/relocation yet (Arc 0).
 */

ENTRY(_start)

RAM_START = 0x40080000;
STACK_SIZE = 0x10000; /* 64 KiB */

SECTIONS {
    . = RAM_START;

    .text : {
        KEEP(*(.text.boot))  /* `_start` must lead the image */
        *(.text .text.*)
    }

    .rodata : { *(.rodata .rodata.*) }
    .data   : { *(.data .data.*) }

    .bss (NOLOAD) : {
        . = ALIGN(16);
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }

    . = ALIGN(16);
    . += STACK_SIZE;
    __stack_top = .;

    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame*) }
}
