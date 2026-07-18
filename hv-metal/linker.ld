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

    /*
     * The EL2 exception vector table (Arc 2). VBAR_EL2[10:0] are RES0, so the table base must be
     * 2 KiB-aligned; we force that alignment here so it is explicit and auditable rather than
     * implied by the input section's attributes (the vector `global_asm!` also `.balign 0x800`s).
     * The input section is named `.vectors` (not `.text.*`) so the `.text` glob above cannot pull
     * it in and defeat this alignment. KEEP: nothing calls the table statically — it is reached
     * only via VBAR_EL2 at runtime — so it must not be garbage-collected.
     */
    . = ALIGN(0x800);
    .vectors : { KEEP(*(.vectors)) }

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

    /*
     * The boot stack grows down from __stack_top toward .bss. There is no guard page: a deep
     * enough overflow would silently corrupt .bss/.rodata/.text. 64 KiB is ample for this no_std
     * bring-up (no recursion, no large stack buffers); revisit if that changes or on real hardware.
     */
    . = ALIGN(16);
    . += STACK_SIZE;
    __stack_top = .;

    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame*) }
}
