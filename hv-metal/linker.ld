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
EXC_STACK_SIZE = 0x4000; /* 16 KiB — the EL2 exception stack (Arc 4) */

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

    /*
     * The dedicated EL2 exception stack (M4 Arc 4). Guest trap-and-service runs the vector
     * handler on SP_EL2 switched to this region — separate from the boot stack, which rust_main
     * abandons the moment it `eret`s into the guest (that path is terminal). One frame deep per
     * trap (saved + restored around each service), so 16 KiB is generous. Arc 2's diagnostic
     * handler had no save-frame and needed no such stack; resuming a guest does.
     */
    . = ALIGN(16);
    . += EXC_STACK_SIZE;
    __exc_stack_top = .;

    /*
     * Guest RAM (M4 Arc 4). A dedicated, 2 MiB-aligned NOLOAD region the hypervisor loads the
     * guest image into (a copy of the in-image guest template) and identity-maps with a single
     * Stage-2 2 MiB block. 2 MiB-aligned + exactly 2 MiB so the block maps ONLY guest RAM — the
     * hypervisor's own memory is deliberately outside the guest's IPA space (no isolation content
     * yet; that honesty is what Arc 5's negative-isolation test builds on). NOLOAD: it reserves
     * DRAM (the `virt` machine has ample) without bloating the image, and _start's `.bss` zeroing
     * does not reach here — the guest bytes are written by the boot-time copy, not relied on zero.
     */
    . = ALIGN(0x200000);
    __guest_ram_start = .;
    . += 0x200000;
    __guest_ram_end = .;

    /*
     * Guest DATA frames (M4 Arc 5). A separate, 2 MiB-aligned NOLOAD region backing the model's
     * per-frame `p2m` mappings — deliberately DISTINCT from the guest image window above so the
     * isolation surface under Architecture Audit #2 is cleanly separable from the infrastructure
     * that merely runs the guest. Each model machine frame `m` the guest is authorized to reach is
     * backed at `__guest_data_start + m * 4 KiB` (host PA) and mapped by Stage-2 at a distinct
     * guest IPA (`stage2::DATA_IPA_BASE + m * 4 KiB`) — IPA != PA, so the emitted table does a real
     * translation, not an identity pass-through. 2 MiB is far more than the handful of 4 KiB frames
     * the negative-isolation test uses, and 2 MiB alignment keeps it its own Stage-2 L2 region.
     * NOLOAD: reserves DRAM without bloating the image; the hypervisor seeds these frames at boot
     * via the realized `hv_hal::GuestMemory`, so their contents are written, not relied upon zero.
     */
    . = ALIGN(0x200000);
    __guest_data_start = .;
    . += 0x200000;
    __guest_data_end = .;

    /DISCARD/ : { *(.comment) *(.note .note.*) *(.eh_frame*) }
}
