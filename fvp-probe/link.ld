/* The FVP Base RevC's non-secure DRAM starts at 0x8000_0000 (TF-A + the model agree). The image is
   loaded there with `-a` (an ELF, so the FVP takes the entry point from the header). */
ENTRY(_start)
SECTIONS
{
  . = 0x80000000;
  .text   : { KEEP(*(.text.boot)) *(.text .text.*) }
  .rodata : { *(.rodata .rodata.*) }
  .data   : { *(.data .data.*) }
  .bss    : { __bss_start = .; *(.bss .bss.* COMMON) __bss_end = .; }
  . = ALIGN(16);
  . += 0x10000;
  __stack_top = .;
}
