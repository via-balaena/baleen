// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # M5 Arc 5e — the real-Linux capstone (feature `real-linux`)
//!
//! The documented drop-in from `docs/ARC-5-M5-GUEST-INTERFACE.md`: boot a **real** aarch64 Linux
//! kernel as a single EL1 guest that "owns the machine", on the interfaces the synthetic Arc 0–5
//! guests already proved sound. **No isolation content** — the thesis (Arcs 0–4) is proven on the
//! un-forgeable synthetic guests; this arc only demonstrates the already-proven hardware interface
//! carries an unmodified kernel. `hv-core`/`hv-hal` are untouched; this whole module is behind the
//! `real-linux` feature, so the default build (the CI boot-test) is byte-for-byte unchanged.
//!
//! ## The model — pass-through, not virtualization
//!
//! A *single* guest owns the real hardware: hv-metal maps the guest RAM window and the GICv3 +
//! PL011 device pages through Stage-2, sets `HCR_EL2.IMO=0` so physical interrupts are delivered
//! straight to the guest's EL1, and lets the kernel drive the real GIC / arch-timer / PL011. The
//! only thing that traps to EL2 is `HVC` (PSCI — Linux's `method = "hvc"`), serviced here. This is
//! the "device pass-through … with `IMO=0`" the Arc-5 doc names; the vGIC list-register injection
//! path (`gic.rs`) is the *multi-guest* mechanism and is not used here.
//!
//! ## The memory contract (shared with `cargo xtask qemu-linux`)
//!
//! QEMU `-device loader` deposits three blobs in guest DRAM before hv-metal runs; hv-metal never
//! copies them — it just points the kernel's boot registers at them. hv-metal owns the low 128 MiB
//! (its image is at `0x4008_0000`); the guest owns `0x4800_0000 .. 0x8000_0000` (needs `-m 1024`).
//!
//! | blob      | guest PA      | how the kernel finds it            |
//! |-----------|---------------|------------------------------------|
//! | `Image`   | `0x4800_0000` | `ELR_EL2` (entry, arm64 boot proto)|
//! | DTB       | `0x4b00_0000` | `x0`                               |
//! | initramfs | `0x4c00_0000` | DTB `/chosen` `linux,initrd-*`     |
//!
//! ## Unsafe
//!
//! As the rest of the metal: Stage-2 table writes (into linker-free interior-mutable storage),
//! EL2 system-register setup, the vector-table `global_asm!`, and the `eret` handoff. Every block
//! carries its justification; the tables live behind `UnsafeCell` (never `static mut`), the same
//! discipline as `stage2.rs`/`guest.rs`.

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::fmt::Write;

use crate::pl011::Pl011;

// ─── the memory contract (must match xtask's `-device loader` addresses) ─────────────────────────

/// Guest RAM base — where the kernel `Image` is loaded and where the DTB's `/memory` starts.
const GUEST_RAM_BASE: u64 = 0x4800_0000;
/// Guest RAM limit (exclusive) — top of the 896 MiB window (`-m 1024` → QEMU RAM ends at 0x8000_0000).
const GUEST_RAM_END: u64 = 0x8000_0000;
/// Kernel `Image` load address (2 MiB-aligned, at the base of guest RAM). `ELR_EL2` entry.
const KERNEL_ENTRY: u64 = 0x4800_0000;
/// Flattened device tree (DTB) load address — handed to the kernel in `x0`.
const DTB_ADDR: u64 = 0x4b00_0000;

/// Low peripheral window mapped as device memory (GICv3 dist 0x0800_0000 + redist 0x080a_0000,
/// PL011 0x0900_0000 all fall inside): `0x0800_0000 .. 0x0a00_0000` (32 MiB).
const DEV_BASE: u64 = 0x0800_0000;
const DEV_END: u64 = 0x0a00_0000;

// ─── AArch64 Stage-2 descriptor encodings (4 KiB granule; 2 MiB blocks at L2) ────────────────────
// Independently the same field layout `stage2.rs` uses, plus a Device-nGnRnE attribute for the
// pass-through peripheral window. Re-derived from the Arm ARM (VMSAv8-64 Stage-2 descriptor format).

/// L1/L2 table descriptor (points at the next-level table): low bits 0b11.
const DESC_TABLE: u64 = 0b11;
/// L2 block (2 MiB leaf): low bits 0b01.
const DESC_BLOCK: u64 = 0b01;
/// 2 MiB block output-address mask (bits [47:21]).
const ADDR_2M: u64 = 0x0000_ffff_ffe0_0000;
/// Next-table output-address mask (bits [47:12]).
const ADDR_4K: u64 = 0x0000_ffff_ffff_f000;

/// `AF=1` (bit 10) and `S2AP=RW` (bits [7:6] = 0b11), shared by every leaf we emit.
const LEAF_AF_RW: u64 = (1 << 10) | (0b11 << 6);
/// Normal, Inner+Outer Write-Back cacheable (`MemAttr=0b1111`, bits [5:2]) + Inner-Shareable
/// (`SH=0b11`, bits [9:8]) — the guest-RAM attribute, executable (no XN, the kernel runs from it).
const BLOCK_NORMAL_RWX: u64 = DESC_BLOCK | LEAF_AF_RW | (0b1111 << 2) | (0b11 << 8);
/// Device-nGnRnE (`MemAttr=0b0000`), execute-never (bit 54) — the GIC/PL011 pass-through attribute.
const BLOCK_DEVICE: u64 = DESC_BLOCK | LEAF_AF_RW | (1 << 54);

/// `VTCR_EL2` — identical to the synthetic path (`guest.rs`): 4 KiB granule, 39-bit IPA (T0SZ=25),
/// start level 1 (so L1 is indexed by IPA[38:30]), Normal WB IS walks, 40-bit PS, `DS=0`.
const VTCR_EL2: u64 =
    (1 << 31) | (0b010 << 16) | (0b11 << 12) | (0b01 << 10) | (0b01 << 8) | (0b01 << 6) | 25;
/// `HCR_EL2.VM` — bit 0, enable Stage-2 for EL1&0. OR'd onto the Arc-3 base (`RW`); `IMO` stays 0.
const HCR_EL2_VM: u64 = 1 << 0;
/// The VMID stamped into `VTTBR_EL2[55:48]`. One guest, so any nonzero VMID; 1, as the single-domain
/// synthetic phases use.
const GUEST_VMID: u64 = 1;

/// `SPSR_EL2` to `eret` into the kernel: EL1h (`M[3:0]=0b0101`, uses `SP_EL1`), AArch64, `DAIF`
/// masked — the arm64 boot protocol enters with interrupts off; the kernel unmasks them itself.
const SPSR_EL2_LINUX: u64 = 0b0101 | (0b1111 << 6);

/// `SCTLR_EL1` enables the kernel must be entered with CLEAR (arm64 boot protocol: MMU off, D-cache
/// off): `M` (0), `A` (1), `C` (2), `SA` (3), `SA0` (4), `I` (12).
const SCTLR_EL1_ENABLES: u64 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 12);

// ─── Stage-2 tables ──────────────────────────────────────────────────────────────────────────────

/// A 4 KiB Stage-2 translation table (512 × 8-byte descriptors), interior-mutable so it is built at
/// runtime without a `static mut`; 4 KiB-aligned for the walk hardware.
#[repr(C, align(4096))]
struct Table(UnsafeCell<[u64; 512]>);
// SAFETY: single-CPU bring-up (secondaries stay PSCI-parked in `_start`); each table is written once,
// before Stage-2 is enabled, then read only by the walk hardware. Same discipline as `stage2.rs`.
unsafe impl Sync for Table {}

/// The single guest's Stage-2 tables: an `L1` (entry 0 → the device region's `L2`, entry 1 → the
/// guest-RAM region's `L2`), an `L2` covering `0x0..0x4000_0000` (device blocks), and an `L2`
/// covering `0x4000_0000..0x8000_0000` (RAM blocks).
static L1: Table = Table(UnsafeCell::new([0; 512]));
static L2_DEV: Table = Table(UnsafeCell::new([0; 512]));
static L2_RAM: Table = Table(UnsafeCell::new([0; 512]));

/// Build the big identity Stage-2 (guest RAM Normal WB RWX + the GIC/PL011 device window) and return
/// the `VTTBR_EL2` value (`L1` PA | VMID). Identity IPA==PA throughout — this is infrastructure that
/// gives the single guest the machine, NOT the model-driven isolation refinement (`stage2.rs`).
fn build_stage2() -> u64 {
    let l1 = L1.0.get();
    let l2_dev = L2_DEV.0.get();
    let l2_ram = L2_RAM.0.get();
    let l1_pa = l1 as *const u8 as u64;
    let l2_dev_pa = l2_dev as *const u8 as u64;
    let l2_ram_pa = l2_ram as *const u8 as u64;

    // SAFETY: single-CPU, built before `enable_stage2` publishes it; EL2 runs MMU-off/identity so no
    // walker observes these stores mid-build. Every table is 4 KiB-aligned with 512 entries, so all
    // indices below (masked to 9 bits) are in range. The device region lives in L1[0], guest RAM in
    // L1[1], so the two L1 writes never collide.
    unsafe {
        (*l1)[0] = (l2_dev_pa & ADDR_4K) | DESC_TABLE; // 0x0..0x4000_0000
        (*l1)[1] = (l2_ram_pa & ADDR_4K) | DESC_TABLE; // 0x4000_0000..0x8000_0000

        // Device pass-through: GICv3 + PL011, 2 MiB device blocks.
        let mut a = DEV_BASE;
        while a < DEV_END {
            let idx = ((a >> 21) & 0x1ff) as usize;
            (*l2_dev)[idx] = (a & ADDR_2M) | BLOCK_DEVICE;
            a += 0x20_0000;
        }

        // Guest RAM: Normal WB RWX, 2 MiB blocks over the whole window.
        let mut a = GUEST_RAM_BASE;
        while a < GUEST_RAM_END {
            let idx = ((a >> 21) & 0x1ff) as usize;
            (*l2_ram)[idx] = (a & ADDR_2M) | BLOCK_NORMAL_RWX;
            a += 0x20_0000;
        }
    }

    l1_pa | (GUEST_VMID << 48)
}

/// Program + enable Stage-2: write `VTCR_EL2`/`VTTBR_EL2`, set `HCR_EL2.VM` (leaving `IMO=0`), then
/// TLB-invalidate for the VMID and synchronize. Load-bearing on silicon, invisible under QEMU/TCG.
fn enable_stage2(vttbr: u64) {
    // SAFETY: all EL2-legal system registers; `HCR_EL2` read-modify-write adds `VM` while keeping the
    // Arc-3 `RW` bit and leaving `IMO`/`FMO` clear (physical interrupts to EL1). Stage-2 affects only
    // EL1&0, never EL2's own MMU-off/identity accesses.
    unsafe {
        asm!(
            "msr vtcr_el2, {vtcr}",
            "msr vttbr_el2, {vttbr}",
            "mrs {tmp}, hcr_el2",
            "orr {tmp}, {tmp}, {vm}",
            "msr hcr_el2, {tmp}",
            "dsb ish",
            "tlbi vmalls12e1is",
            "dsb ish",
            "isb",
            vtcr = in(reg) VTCR_EL2,
            vttbr = in(reg) vttbr,
            vm = in(reg) HCR_EL2_VM,
            tmp = out(reg) _,
            options(nostack),
        );
    }
}

/// Let the guest (EL1) use the GICv3 system-register CPU interface and the arch timer without
/// trapping to EL2: `ICC_SRE_EL2` = SRE + Enable (so `ICC_SRE_EL1` is accessible), and
/// `CNTHCTL_EL2` = EL1PCTEN|EL1PCEN (no physical counter/timer trap). The kernel drives the real GIC
/// and virtual timer directly; hv-metal does NOT pre-init the physical GIC (Linux does).
fn enable_guest_hw_access() {
    const ICC_SRE_EL2_SRE_EN: u64 = (1 << 0) | (1 << 3);
    const CNTHCTL_EL1_TIMER: u64 = (1 << 0) | (1 << 1);
    // SAFETY: `ICC_SRE_EL2` and `CNTHCTL_EL2` are EL2 control registers; we set only the documented
    // enable bits (read-modify-write for SRE to preserve IMPDEF bits), `isb` before the guest relies
    // on the interface. No memory effect.
    unsafe {
        asm!(
            "mrs {t}, ICC_SRE_EL2",
            "orr {t}, {t}, {sre}",
            "msr ICC_SRE_EL2, {t}",
            "msr CNTHCTL_EL2, {cnt}",
            "isb",
            t = out(reg) _,
            sre = in(reg) ICC_SRE_EL2_SRE_EN,
            cnt = in(reg) CNTHCTL_EL1_TIMER,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Clear the guest's `SCTLR_EL1` enables (MMU/caches off) so the kernel is entered Stage-1-off from a
/// known state, as the arm64 boot protocol requires. RES1 bits are preserved (read-modify-write).
fn init_guest_el1() {
    // SAFETY: `SCTLR_EL1` is writable from EL2; the read-modify-write clears exactly the enable bits
    // and preserves RES1. No memory effect.
    unsafe {
        asm!(
            "mrs {tmp}, sctlr_el1",
            "bic {tmp}, {tmp}, {en}",
            "msr sctlr_el1, {tmp}",
            en = in(reg) SCTLR_EL1_ENABLES,
            tmp = out(reg) _,
            options(nomem, nostack),
        );
    }
}

// ─── the Linux-mode EL2 exception vectors ────────────────────────────────────────────────────────
// A dedicated vector table installed just before the `eret` into Linux — separate from the synthetic
// path's (`exceptions.rs`), so the synthetic code is untouched. Slot 8 (lower-EL sync) → the PSCI /
// abort handler below; every other slot → the diagnostic reporter (`handle_exception`, reused).
// With `IMO=0` the guest's device interrupts go straight to its EL1, so EL2 sees no guest IRQs.

global_asm!(
    r#"
    .section .text
    .balign 0x800
    .global __linux_vectors
__linux_vectors:
    .macro lventry index
    .balign 0x80
    mov     w0, #\index
    b       __linux_diag
    .endm

    lventry 0    // Current EL SP0 — Sync
    lventry 1
    lventry 2
    lventry 3
    lventry 4    // Current EL SPx — Sync (EL2's own faults land here)
    lventry 5
    lventry 6
    lventry 7
    // 0x400 Lower EL AArch64 — Sync: the guest's HVC (PSCI) and any Stage-2 abort. Straight to the
    // trampoline (must not clobber the guest's x0 = PSCI function id).
    .balign 0x80
    b       __linux_sync_entry
    lventry 9    // 0x480 Lower EL AArch64 — IRQ (dormant: IMO=0 routes guest IRQs to EL1)
    lventry 10
    lventry 11
    lventry 12
    lventry 13
    lventry 14
    lventry 15

    .balign 0x80
__linux_diag:
    bl      handle_exception     // -> ! (reports EC/ELR/FAR/ESR and parks); w0 = slot index
0:  wfe
    b       0b
    "#
);

// The lower-EL sync trampoline: save x0..x30, call the Rust handler (which may set x0 = the PSCI
// return value), restore, and `eret` to resume the kernel past its `HVC`. Same save/restore
// discipline as `guest.rs`'s `__guest_sync_entry`.
global_asm!(
    r#"
    .section .text
    .balign 0x40
    .global __linux_sync_entry
__linux_sync_entry:
    sub     sp, sp, #(16 * 16)
    stp     x0, x1,   [sp, #(16 * 0)]
    stp     x2, x3,   [sp, #(16 * 1)]
    stp     x4, x5,   [sp, #(16 * 2)]
    stp     x6, x7,   [sp, #(16 * 3)]
    stp     x8, x9,   [sp, #(16 * 4)]
    stp     x10, x11, [sp, #(16 * 5)]
    stp     x12, x13, [sp, #(16 * 6)]
    stp     x14, x15, [sp, #(16 * 7)]
    stp     x16, x17, [sp, #(16 * 8)]
    stp     x18, x19, [sp, #(16 * 9)]
    stp     x20, x21, [sp, #(16 * 10)]
    stp     x22, x23, [sp, #(16 * 11)]
    stp     x24, x25, [sp, #(16 * 12)]
    stp     x26, x27, [sp, #(16 * 13)]
    stp     x28, x29, [sp, #(16 * 14)]
    str     x30,      [sp, #(16 * 15)]
    mov     x0, sp
    bl      handle_linux_sync
    ldp     x0, x1,   [sp, #(16 * 0)]
    ldp     x2, x3,   [sp, #(16 * 1)]
    ldp     x4, x5,   [sp, #(16 * 2)]
    ldp     x6, x7,   [sp, #(16 * 3)]
    ldp     x8, x9,   [sp, #(16 * 4)]
    ldp     x10, x11, [sp, #(16 * 5)]
    ldp     x12, x13, [sp, #(16 * 6)]
    ldp     x14, x15, [sp, #(16 * 7)]
    ldp     x16, x17, [sp, #(16 * 8)]
    ldp     x18, x19, [sp, #(16 * 9)]
    ldp     x20, x21, [sp, #(16 * 10)]
    ldp     x22, x23, [sp, #(16 * 11)]
    ldp     x24, x25, [sp, #(16 * 12)]
    ldp     x26, x27, [sp, #(16 * 13)]
    ldp     x28, x29, [sp, #(16 * 14)]
    ldr     x30,      [sp, #(16 * 15)]
    add     sp, sp, #(16 * 16)
    eret
    "#
);

extern "C" {
    fn __linux_sync_entry() -> !;
    /// Reused from `exceptions.rs`: report `(EC/ELR/FAR/ESR)` for slot index `w0` and park.
    fn handle_exception(vector: u64) -> !;
    static __linux_vectors: u8;
}

/// The saved GPR frame the sync trampoline hands the Rust handler: `x[i]` = `x<i>` for `i` in 0..=30.
#[repr(C)]
struct LinuxFrame {
    x: [u64; 31],
}

// PSCI function IDs (SMC Calling Convention) — the same set `guest.rs`'s Arc-5c handler services.
const PSCI_VERSION_FID: u64 = 0x8400_0000;
const PSCI_FEATURES_FID: u64 = 0x8400_000A;
const PSCI_SYSTEM_OFF_FID: u64 = 0x8400_0008;
const PSCI_VERSION_1_1: u64 = 0x0001_0001;
const PSCI_NOT_SUPPORTED: u64 = (-1i64) as u64;

/// The Linux-mode lower-EL synchronous handler. `HVC` → service PSCI (Linux's `method = "hvc"`).
/// Anything else (a Stage-2 abort, an unexpected trapped instruction) is a bring-up bug: report it
/// with full syndrome and park, so the fault is diagnosable rather than a silent hang.
///
/// # Safety
/// `frame` is the valid `&mut LinuxFrame` the trampoline saved on the exception stack.
#[no_mangle]
extern "C" fn handle_linux_sync(frame: *mut LinuxFrame) {
    let (esr, elr, far) = read_syndrome();
    let ec = (esr >> 26) & 0x3f;
    let mut uart = crate::uart();

    // EC 0x16 = HVC (AArch64). The only thing that should trap to EL2 in pass-through mode.
    if ec == 0x16 {
        // SAFETY: the trampoline gave us its on-stack frame; single-CPU, non-nested.
        let frame = unsafe { &mut *frame };
        match frame.x[0] {
            PSCI_VERSION_FID => frame.x[0] = PSCI_VERSION_1_1,
            PSCI_FEATURES_FID => {
                frame.x[0] = if frame.x[1] == PSCI_SYSTEM_OFF_FID {
                    0
                } else {
                    PSCI_NOT_SUPPORTED
                };
            }
            PSCI_SYSTEM_OFF_FID => {
                let _ = writeln!(
                    uart,
                    "baleen: linux guest issued PSCI SYSTEM_OFF — a real Linux kernel booted and shut \
                     down on hv-metal's EL2 (M5 Arc 5e)"
                );
                semihosting_exit(); // clean QEMU exit (falls through to a fault→park if -semihosting off)
            }
            other => {
                frame.x[0] = PSCI_NOT_SUPPORTED;
                let _ = writeln!(
                    uart,
                    "baleen: linux PSCI FID 0x{other:08x} -> NOT_SUPPORTED"
                );
            }
        }
        return;
    }

    // Not an HVC: a genuine fault. Report and halt (the diagnostic that drives bring-up).
    let _ = writeln!(
        uart,
        "baleen: LINUX GUEST TRAP: EC=0x{ec:02x} ELR=0x{elr:016x} FAR=0x{far:016x} ESR=0x{esr:08x} — halting"
    );
    crate::park();
}

/// Cleanly exit QEMU via the ARM semihosting `SYS_EXIT` call (the `qemu-linux` target passes
/// `-semihosting`). Used on the guest's PSCI `SYSTEM_OFF` so the demo terminates instead of parking
/// until an external timeout. If `-semihosting` is not enabled, `hlt #0xf000` faults to EL2 and the
/// diagnostic vector parks — so this is safe either way.
fn semihosting_exit() -> ! {
    // AArch64 `SYS_EXIT` (op 0x18): `x1` -> `[reason, exit_code]`; `ADP_Stopped_ApplicationExit` =
    // 0x20026 → QEMU exits with the given code (0).
    static EXIT_BLOCK: [u64; 2] = [0x2_0026, 0];
    // SAFETY: `hlt #0xf000` is the AArch64 semihosting trap; EL2 runs MMU-off/identity so
    // `&EXIT_BLOCK` is a physical address QEMU reads directly. Never returns (QEMU exits, or the
    // instruction faults to the EL2 vector, which parks).
    unsafe {
        asm!(
            "mov x0, #0x18",
            "mov x1, {b}",
            "hlt #0xf000",
            b = in(reg) core::ptr::addr_of!(EXIT_BLOCK),
            options(nostack, noreturn),
        );
    }
}

/// Read `(ESR_EL2, ELR_EL2, FAR_EL2)`.
fn read_syndrome() -> (u64, u64, u64) {
    let (esr, elr, far): (u64, u64, u64);
    // SAFETY: EL2 syndrome registers, readable at EL2; no memory effect.
    unsafe {
        asm!(
            "mrs {0}, esr_el2",
            "mrs {1}, elr_el2",
            "mrs {2}, far_el2",
            out(reg) esr, out(reg) elr, out(reg) far,
            options(nomem, nostack, preserves_flags),
        );
    }
    (esr, elr, far)
}

// Install the Linux vector table and `eret` into the kernel. `x0` = DTB PA (arm64 boot protocol),
// `x1` = EL2 exception-stack top (becomes `SP_EL2` for later HVC/abort traps). `ELR_EL2`/`SPSR_EL2`
// are set by the caller before the `bl` here.
global_asm!(
    r#"
    .section .text
    .global __enter_linux
__enter_linux:
    // x0 = dtb_pa, x1 = exc_stack_top
    mov     sp, x1              // SP_EL2 for future traps
    mov     x1, xzr             // arm64 boot protocol: x1..x3 = 0
    mov     x2, xzr
    mov     x3, xzr
    dsb     sy
    isb
    eret                        // -> EL1 kernel entry (ELR_EL2), with x0 = DTB
    "#
);

extern "C" {
    fn __enter_linux(dtb_pa: u64, exc_stack_top: u64) -> !;
}

extern "C" {
    static __exc_stack_top: u8;
}

/// The Arc-5e entry: build the pass-through Stage-2, enable it (`IMO=0`), let the guest reach the
/// GIC/timer, point `ELR_EL2` at the loaded kernel `Image`, install the Linux vectors, and `eret`
/// into a real Linux kernel with `x0` = the DTB. Never returns (transfers to EL1).
pub(crate) fn run(uart: &mut Pl011) -> ! {
    let _ = writeln!(
        uart,
        "baleen: M5 Arc 5e — booting a REAL aarch64 Linux kernel as a single EL1 guest \
         (Image@0x{KERNEL_ENTRY:08x}, DTB@0x{DTB_ADDR:08x}, RAM 0x{GUEST_RAM_BASE:08x}..0x{GUEST_RAM_END:08x})"
    );

    let vttbr = build_stage2();
    enable_stage2(vttbr);
    enable_guest_hw_access();
    init_guest_el1();

    // Boot registers: SPSR = EL1h/DAIF-masked, ELR = kernel entry.
    // SAFETY: `SPSR_EL2`/`ELR_EL2` are RW at EL2; they seed the state `eret` restores.
    unsafe {
        asm!(
            "msr spsr_el2, {spsr}",
            "msr elr_el2, {elr}",
            spsr = in(reg) SPSR_EL2_LINUX,
            elr = in(reg) KERNEL_ENTRY,
            options(nomem, nostack, preserves_flags),
        );
    }

    // Install the Linux vector table (VBAR_EL2), replacing the synthetic-path table for this boot.
    // SAFETY: `VBAR_EL2` is RW at EL2; `__linux_vectors` is the 2 KiB-aligned in-image table.
    unsafe {
        let vec = core::ptr::addr_of!(__linux_vectors) as u64;
        asm!("msr vbar_el2, {v}", "isb", v = in(reg) vec, options(nomem, nostack));
    }

    let _ = writeln!(uart, "baleen: entering EL1 — the kernel takes the machine");

    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    // SAFETY: transfers to EL1 via `eret`; `DTB_ADDR` is the loaded DTB, `exc_stack_top` the EL2
    // trap stack. Never returns.
    unsafe { __enter_linux(DTB_ADDR, exc_stack_top) }
}
