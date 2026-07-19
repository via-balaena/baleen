// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Trap-and-service — the proof touches a guest (M4 Arc 4)
//!
//! Arc 3 ran the proven brain on the metal but *pre-guest*: a synthetic `HvCall` dispatched from
//! EL2 itself. Arc 4 (see `docs/ROADMAP.md`) is the first time a **real EL1 guest** drives the
//! brain. A trivial guest issues `HVC`; the CPU traps it to EL2; this module saves the guest
//! register frame, decodes it through `hv-core`'s ABI-decode seam, routes it through the **actual**
//! [`hv_core::Hypervisor::dispatch`], writes the result back into the guest's `x0`, and `eret`s so
//! the guest observes it. The guest hands the serviced balance back in a final `HVC` — a witness,
//! produced *by the guest*, that the round trip reached its register file.
//!
//! ## What Arc 4 is (and is not)
//!
//! - **Is:** EL1 entry (`eret` with `SPSR_EL2`/`ELR_EL2`), a minimal Stage-2 (`HCR_EL2.VM=1` + a
//!   single 2 MiB identity block mapping just the guest's RAM), the `HVC` synchronous trap
//!   (`EC=0x16`, lower-EL/AArch64/sync = vector slot 8), a GPR **save/restore frame** on a
//!   dedicated exception stack (the exact thing Arc 2's diagnostic handler deferred — it halted and
//!   never resumed, so it needed none), decode → dispatch → result, and `eret` to resume.
//! - **Is not:** any isolation content. The Stage-2 map is *just enough to run the guest*; it does
//!   not yet come from the model's `p2m`, and there is **no** negative-isolation test. Translating
//!   `p2m` into faithful Stage-2 descriptors and faulting a guest that touches unauthorized memory
//!   is **Arc 5** (Architecture Audit #2). Arc 4 *refines* the proof (the model's dispatch, driven
//!   for a real guest on real — emulated — hardware); it proves no isolation property.
//!
//! ## The decode seam
//!
//! The guest presents raw register values (`x0` = hypercall number, `x1` = argument, by
//! convention). Those flow through [`hv_core::Hypercall::decode`] — the same pure, fuzzed
//! `RawHypercall` → typed decoder `hv-fuzz` hammers — and the typed [`hv_core::Hypercall`] is
//! mapped to an [`hv_core::HvCall`] and routed through [`hv_core::Hypervisor::dispatch`], the proven
//! integrated brain. That `Hypercall` → `HvCall` map is **stand-in personality glue**: at M5 the
//! `baleen-xenabi` personality owns the whole wire-format → `HvCall` decode and this hand-mapping
//! goes away (`hv-core`'s own docs flag the seam). The core never sees a register; the metal never
//! sees an operation's meaning — exactly the split the fence draws.
//!
//! ## The QEMU-vs-metal line, drawn per mechanism (design-lesson #23; `docs/QEMU-AND-METAL.md`)
//!
//! - **`eret` / exception entry / the `HVC` trap** — QEMU models the ARMv8-A exception model
//!   faithfully at the architectural level, so it is a **sound third oracle** for this arc: a green
//!   round trip is real evidence the trap decodes and the dispatch returns the right value.
//! - **`ELR_EL2` for `HVC`** — the preferred return address of an `SVC`/`HVC`/`SMC` is the
//!   instruction *after* it (unlike an abort, which returns to the faulting instruction), so the
//!   handler does **not** advance `ELR_EL2`; `eret` resumes the guest past the `HVC`. Both true on
//!   QEMU and metal.
//! - **Stage-2 TLB maintenance + barriers** — after programming `VTTBR_EL2`/`VTCR_EL2` and setting
//!   `HCR_EL2.VM`, real silicon needs a `tlbi` (Stage-1&2 by VMID) + `dsb`/`isb` before the guest's
//!   first access; QEMU's TCG would tolerate omitting them, but they are correct on metal, so we
//!   emit them (invisible-under-emulation, load-bearing-on-silicon — the weak-memory blind spot).
//! - **Guest Stage-1 off** — the guest runs with `SCTLR_EL1.M=0`, so its virtual addresses are its
//!   IPAs (input to Stage-2). With Stage-1 off and `HCR_EL2.DC=0`, *data* accesses default to
//!   Device-nGnRnE and *instruction fetches* to Normal — but the trivial guest does no data access
//!   (pure register ops + `HVC`), and instruction fetch from our **Normal, non-execute-never**
//!   Stage-2 block executes on both QEMU and silicon. That the block is Normal (not Device) is a
//!   hard silicon requirement, not decoration: a fetch from Device memory *faults* on real hardware
//!   though TCG would let it slide — the per-mechanism line again. We force the `SCTLR_EL1` enables
//!   off by read-modify-write (preserving `RES1`) because its reset value is architecturally
//!   UNKNOWN on real hardware (QEMU gives a clean one), and leave `DC=0` since no data access needs
//!   Normal typing.
//!
//! ## The crate-wide real-hardware gap this per-mechanism list does NOT close
//!
//! The lines above draw the QEMU-vs-metal boundary for each mechanism Arc 4 *adds*, but a
//! diamond-grade review (the Arc-4 review pass) found a deeper, crate-wide gap they do not reach:
//! **EL2 itself runs with its own stage-1 MMU off** (`SCTLR_EL2.M=0`, never enabled in `_start` or
//! anywhere), so on real silicon *every EL2 data access is Device-nGnRnE*. Two consequences, both
//! **invisible under QEMU/TCG** (which ignores memory type):
//!
//! 1. **Atomics are architecturally UNPREDICTABLE.** `LDXR/STXR` (and LSE atomics) on Device memory
//!    are CONSTRAINED UNPREDICTABLE — the common outcome is a perpetually-failing `STXR`, i.e. a
//!    livelock. This reaches [`IN_GUEST_HANDLER`] here and, pre-existing since Arc 3, the bump
//!    allocator's `compare_exchange`.
//! 2. **Caches are unmanaged.** Freshly-copied guest code is written (uncached) then fetched
//!    (cacheable) with no I-cache maintenance; the Stage-2 table walker is programmed cacheable
//!    (`VTCR_EL2.IRGN0/ORGN0`) while its descriptors are written by uncached stores. On silicon
//!    either can read stale lines out of the UNKNOWN reset cache state.
//!
//! This is **not Arc-4-specific** (it spans arcs 0–4), does **not** affect QEMU or the proof, and is
//! within the metal's already-declared *real-HW-deferred* scope — but it *is* the real distance
//! between "QEMU-sound" and "runs on metal." The single clean fix is a named prerequisite arc for
//! the first real-hardware run: an **EL2 stage-1 Normal-cacheable identity map + `SCTLR_EL2.M/C/I` +
//! boot-time I/D-cache invalidation**, which closes atomics *and* caches together. Its core payoff
//! (atomics no longer UNPREDICTABLE) can only be *validated* on real EL2 silicon — no current oracle
//! (spec, blind auditor, QEMU) can — so naming it here is the honest diamond for it, in the spirit of
//! `docs/TIER-D-NONINTERFERENCE.md` §2.1. See `docs/ARC-4-TRAP-AND-SERVICE.md` ("Real-hardware
//! readiness"). Until then, treat a green QEMU boot as *functional* evidence only.
//!
//! ## Unsafe
//!
//! System-register writes (`VTCR_EL2`, `VTTBR_EL2`, `HCR_EL2`, `SCTLR_EL1`, `ELR_EL2`, `SP_EL1`,
//! `SPSR_EL2`), the `eret`, the vector trampoline's GPR save/restore, and building the Stage-2
//! tables + copying the guest image into guest RAM (raw pointers into linker-reserved regions). All
//! EL2-legal on `virt`; each block carries its justification. The Stage-2 tables and the global
//! `Hypervisor` live behind `UnsafeCell` (never `static mut`), the same discipline `heap.rs` uses.

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hv_core::{HvCall, HvOutcome, Hypercall, Hypervisor, RawHypercall};

use crate::pl011::Pl011;

// ---------------------------------------------------------------------------------------------
// The trivial guest.
//
// A handful of position-independent AArch64 instructions whose only job is to exercise the round
// trip. It lives in the hypervisor image as a `.rodata` *template* (never executed in place); the
// hypervisor copies it into guest RAM and `eret`s to the copy. Every instruction is a `mov`
// immediate, an `hvc`, or a relative branch, so a verbatim byte copy runs correctly wherever it
// lands (the `b 0b` offset is relative and survives the copy).
//
//   grant 100  -> hypervisor services CreditGrant(100) -> x0 = 100
//   spend  30  -> hypervisor services CreditSpend(30)  -> x0 = 70   (proves the FIRST resume worked)
//   report 70  -> guest echoes the balance it received; the hypervisor asserts it equals the 70 it
//                 last returned. 70 is no call's *input*, so echoing it proves the guest observed
//                 the *serviced* result, not merely a value it was handed to pass through.
//
// `x0` carries the hypercall number, `x1` the argument (the `RawHypercall` convention). The result
// comes back in `x0`.
// ---------------------------------------------------------------------------------------------
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .global __guest_tpl_start
__guest_tpl_start:
    mov     x0, #0          // NR_GRANT
    mov     x1, #100        // amount = 100
    hvc     #0              // -> x0 = 100
    mov     x0, #1          // NR_SPEND
    mov     x1, #30         // amount = 30
    hvc     #0              // -> x0 = 70
    mov     x1, x0          // echo = the balance we received (70)
    mov     x0, #0xff       // NR_GUEST_REPORT (metal-local; hv-core's decoder rejects it)
    hvc     #0              // -> the hypervisor witnesses the round trip; this HVC does not return
0:  wfe                     // belt-and-suspenders: the report handler is terminal
    b       0b
    .global __guest_tpl_end
__guest_tpl_end:
    "#
);

/// Hypercall number the guest uses to report the balance it observed. Chosen outside `hv-core`'s
/// decoder range (it knows only `NR_GRANT=0`/`NR_SPEND=1`) so it is unambiguously a metal-local
/// diagnostic call, handled here and never routed into the brain.
const NR_GUEST_REPORT: u64 = 0xff;

/// The acting domain for the guest's hypercalls: dom0 (slot 0), `Live` from boot with a credit
/// account. A single-domain guest is all Arc 4 needs; multi-domain guests are later.
const DOM0: hv_core::hypervisor::DomId = 0;

/// Sentinel returned to the guest in `x0` when a hypercall is rejected (bad number, oversized
/// argument, or a subsystem refusal). `u64::MAX` is out of range for any real balance.
const HVCALL_REJECTED: u64 = u64::MAX;

/// The balance the guest is expected to observe and echo (`grant 100`, `spend 30` → `70`). The
/// witness value: deterministic, and not equal to any hypercall input.
const EXPECTED_BALANCE: u64 = 70;

// ---------------------------------------------------------------------------------------------
// Minimal Stage-2: a single 2 MiB identity block mapping just the guest's RAM.
//
// 4 KiB granule, 39-bit IPA (T0SZ=25) so translation starts at level 1 with a SINGLE 512-entry
// table (no concatenation): L1 (1 GiB/entry) -> L2 (2 MiB block). Identity (IPA == PA) keeps the
// bring-up easy to reason about; Arc 5 replaces the whole thing with per-frame descriptors emitted
// from the model's `p2m` (and adds the negative-isolation test — Architecture Audit #2). Values
// re-derived independently from the Arm ARM by a spec-blind auditor and converged (see
// `docs/ARC-4-TRAP-AND-SERVICE.md`); QEMU is the third oracle (a wrong table = the guest never
// fetches and no HVC marker appears).
// ---------------------------------------------------------------------------------------------

/// `VTCR_EL2`: 4 KiB granule (`TG0=0`), 39-bit IPA (`T0SZ=25`), start level 1 (`SL0=0b01`), Normal
/// Inner+Outer WBWA cacheable table walks (`IRGN0=ORGN0=0b01`), Inner Shareable (`SH0=0b11`), 40-bit
/// PA (`PS=0b010`), and the `RES1` bit 31. Assembled from the field encodings in the Arm ARM
/// `VTCR_EL2` description.
///
/// **Below-bar, named by the Arc-4 review:** `PS` is hardcoded to 40-bit rather than derived from
/// `ID_AA64MMFR0_EL1.PARange`. On a CPU whose `PARange < 40-bit` this over-declares the output size
/// (a mis-programming). Harmless here — QEMU `virt`/`-cpu max` supports ≥40-bit and every PA we use
/// is `< 2^31` — but a real-hardware-portability fix reads `PARange` and clamps `PS` to it.
const VTCR_EL2: u64 = (1 << 31)      // RES1
    | (0b010 << 16)                  // PS   = 40-bit PA
    | (0b11 << 12)                   // SH0  = Inner Shareable
    | (0b01 << 10)                   // ORGN0 = Normal WBWA
    | (0b01 << 8)                    // IRGN0 = Normal WBWA
    | (0b01 << 6)                    // SL0  = start at level 1
    | 25; // T0SZ = 64 - 39
          // TG0 = 0b00 (4 KiB) and VS = 0 (8-bit VMID) are the zero fields, left implicit.

/// VMID for the single guest. Nonzero to distinguish it from the "no VMID" default; 8-bit (with
/// `VTCR_EL2.VS=0`) so it sits in `VTTBR_EL2[55:48]`.
const GUEST_VMID: u64 = 1;

/// `HCR_EL2.VM` — bit 0. Enables Stage-2 translation for EL1&0. OR'd onto the Arc-3 `HCR_EL2` (which
/// already set `RW`=bit 31); `TGE`/`HCD` stay 0 so the guest runs as a normal EL1 and its `HVC`
/// traps to EL2.
const HCR_EL2_VM: u64 = 1 << 0;

/// Stage-2 descriptor bits (4 KiB granule).
mod desc {
    /// A table descriptor's low bits (`0b11`); the rest is the next-table PA in bits [47:12].
    pub const TABLE: u64 = 0b11;
    /// Mask for a table descriptor's next-table address (bits [47:12]).
    pub const TABLE_ADDR: u64 = 0x0000_ffff_ffff_f000;
    /// Mask for a 2 MiB block descriptor's output address (bits [47:21]).
    pub const BLOCK_ADDR: u64 = 0x0000_ffff_ffe0_0000;
    /// A 2 MiB block descriptor's low attributes: block (`0b01`), Normal Inner+Outer WB cacheable
    /// (`MemAttr=0b1111`), read/write (`S2AP=0b11`), Inner Shareable (`SH=0b11`), Access Flag set
    /// (`AF=1`, else the first access faults), and execute-*allowed* (`XN=0`, so the guest can fetch
    /// its instructions from this block).
    pub const BLOCK_ATTRS: u64 = 0b01        // block entry (at level 2 = 2 MiB)
        | (0b1111 << 2)                      // MemAttr = Normal WB cacheable
        | (0b11 << 6)                        // S2AP = read/write
        | (0b11 << 8)                        // SH   = Inner Shareable
        | (1 << 10); // AF = 1
}

/// A 4 KiB Stage-2 translation table (512 × 8-byte descriptors), interior-mutable so it can be
/// built at runtime without a `static mut`. `#[repr(C, align(4096))]`: the walk hardware requires a
/// 4 KiB-aligned base.
#[repr(C, align(4096))]
struct Table(UnsafeCell<[u64; 512]>);

// SAFETY: single-CPU bring-up (only the boot CPU runs — secondaries stay PSCI-parked in `_start`),
// and each table is written once, before Stage-2 is enabled, then only read by the walk hardware.
// No two accesses race. Same discipline as `heap.rs`'s arena.
unsafe impl Sync for Table {}

/// The level-1 Stage-2 table (one entry used: the 1 GiB region containing guest RAM → the L2 table).
static STAGE2_L1: Table = Table(UnsafeCell::new([0; 512]));
/// The level-2 Stage-2 table (one entry used: a 2 MiB block identity-mapping guest RAM).
static STAGE2_L2: Table = Table(UnsafeCell::new([0; 512]));

// ---------------------------------------------------------------------------------------------
// The global guest Hypervisor.
//
// The trap handler is reached from the vector table (asm), so the `Hypervisor` it services must be
// reachable as a global. Built once in `run` before the first `eret`, then mutated only by the
// (single-CPU, non-nested) trap handler. `UnsafeCell<Option<_>>` behind a `Sync` newtype — never a
// `static mut` — mirrors `heap.rs`.
// ---------------------------------------------------------------------------------------------
struct HvCell(UnsafeCell<Option<Hypervisor>>);

// SAFETY: as `Table` — single boot CPU, and the only writer is `run` (before any guest runs) plus
// the straight-line, interrupt-masked, non-nested trap handler. No concurrent access exists.
unsafe impl Sync for HvCell {}

static GUEST_HV: HvCell = HvCell(UnsafeCell::new(None));

/// The balance the hypervisor last returned to the guest — remembered across trap invocations so
/// the terminal report can assert the guest echoed back exactly what it was served.
static LAST_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);

/// Re-entry guard for the guest sync-trap handler. Set on entry, cleared before the resume return.
/// The architecture already makes slot 8 non-nesting (it fires only from a *lower* EL, and the
/// handler runs entirely at EL2 with interrupts masked; a fault *inside* the handler vectors to
/// slot 4 — the diagnostic halt handler — not back here), so this never fires. It is a defensive
/// assertion of that invariant, not a witness: it makes "the guest handler is never nested" a
/// runtime-checked fact rather than only an argument. If it ever trips, we halt loudly.
static IN_GUEST_HANDLER: AtomicBool = AtomicBool::new(false);

// Linker-reserved regions (see `linker.ld`): the guest-image template bounds, the dedicated EL2
// exception stack top, and the 2 MiB guest RAM window.
extern "C" {
    static __guest_tpl_start: u8;
    static __guest_tpl_end: u8;
    static __exc_stack_top: u8;
    static __guest_ram_start: u8;
    static __guest_ram_end: u8;
}

/// `SPSR_EL2` to `eret` into the guest: return to EL1 using `SP_EL1` (`EL1h`, `M[3:0]=0b0101`),
/// AArch64 (`M[4]=0`), with `DAIF` (`D,A,I,F` = bits [9:6]) all masked. No async interrupt can then
/// perturb the guest or the handler (there are none anyway).
const SPSR_EL2_GUEST: u64 = 0b0101 | (0b1111 << 6);

/// The guest register frame the vector trampoline saves and restores around servicing: `x0..x30`.
/// `x0` is where the guest's hypercall number arrives and the result is written back; the rest are
/// preserved verbatim so the guest resumes unperturbed. `SP_EL1` is banked (untouched by the EL2
/// handler, which runs on `SP_EL2`) and `ELR_EL2`/`SPSR_EL2` are not modified by the straight-line
/// handler, so none of them belong in the frame.
///
/// **Deferred (named by the Arc-4 review):** the FP/SIMD state (`v0..v31`, `FPSR`/`FPCR`) is *not*
/// framed. The Rust handler can clobber `v`-registers under AArch64 codegen, so a guest that used
/// FP/SIMD and expected it preserved across an `HVC` would be corrupted. Harmless for Arc 4's
/// register-only guest (no FP, and FP is untrapped so no fault); the FP save/restore lands with the
/// first arc that runs a non-trivial guest.
#[repr(C)]
pub struct GuestFrame {
    pub x: [u64; 31],
}

// The vector trampoline for a lower-EL/AArch64 synchronous exception (slot 8 — where the guest's
// `HVC` lands). Runs on `SP_EL2`, already switched to the dedicated exception stack before the first
// `eret`. It must NOT clobber any guest register before saving it, so — unlike the diagnostic
// slots — it does not load a slot index; it saves `x0..x30`, hands the frame pointer to the Rust
// handler, then restores (reloading the handler's update to `x0`) and `eret`s. `handle_guest_sync`
// returns for a serviceable call (resume the guest) and never returns for the terminal report
// (parks) — belt-and-suspenders `wfe` covers a handler that unexpectedly returns.
global_asm!(
    r#"
    .section .text
    .balign 0x40
    .global __guest_sync_entry
__guest_sync_entry:
    sub     sp, sp, #(16 * 16)      // 256 bytes: 31 GPRs (248) + 16-byte alignment pad
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
    mov     x0, sp                  // &GuestFrame -> first C argument
    bl      handle_guest_sync
    ldp     x0, x1,   [sp, #(16 * 0)]   // reloads the possibly-updated x0 (the hypercall result)
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

/// A minimal `hv_hal::VcpuOps` realized on ARM (M4 Arc 4).
///
/// `set_entry` is **realized**: it writes `ELR_EL2`, the address the next `eret` resumes at — the
/// natural ARM meaning of "set the guest entry" (Architecture Audit #1 renamed the parameter from
/// `rip` to `entry` precisely so no register leaks into the fence). `inject_interrupt` is honestly
/// **deferred**: there is no GIC in Arc 4 and nothing to inject, so realizing it would be a fiction;
/// it is unreachable here and reports rather than silently pretending. This is the fence method
/// actually driving hardware for the first time.
struct ArmVcpu;

impl hv_hal::VcpuOps for ArmVcpu {
    fn inject_interrupt(&mut self, _vector: u8) {
        // Deferred (no GIC yet — a later arc). Not on Arc 4's path; if it is ever reached, say so
        // rather than mislead a caller into thinking an interrupt was queued.
        let mut uart = crate::uart();
        let _ = writeln!(
            uart,
            "baleen: VcpuOps::inject_interrupt is unrealized (no GIC until a later arc); halting"
        );
        crate::park();
    }

    fn set_entry(&mut self, entry: u64) {
        // SAFETY: `ELR_EL2` is RW at EL2; it holds the address the next `eret` returns to. Writing
        // it sets the guest's entry PC. No memory effect beyond the register.
        unsafe { asm!("msr elr_el2, {e}", e = in(reg) entry, options(nomem, nostack)) };
    }
}

/// Copy the guest template into guest RAM and return `(entry, stack_top)` guest-physical addresses.
/// The hypervisor "loads the guest image" — the realistic model, and it decouples where the
/// template sits in the hypervisor image from where the guest actually runs.
fn load_guest() -> (u64, u64) {
    // The four symbols are linker-defined region bounds; `addr_of!` reads their addresses without
    // forming a reference to an `extern` static of unknown value. Guest RAM is a reserved, 2 MiB,
    // in-DRAM window (see `linker.ld`); the template is `[tpl_start, tpl_end)` in `.rodata`.
    let tpl_start = core::ptr::addr_of!(__guest_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest_tpl_end) as usize;
    let ram_start = core::ptr::addr_of!(__guest_ram_start) as usize;
    let ram_end = core::ptr::addr_of!(__guest_ram_end) as usize;
    let len = tpl_end - tpl_start;
    // SAFETY: source is the in-image template; destination is the start of the reserved guest RAM
    // window, which is far larger than the template. Non-overlapping distinct regions.
    unsafe {
        core::ptr::copy_nonoverlapping(tpl_start as *const u8, ram_start as *mut u8, len);
    }
    // Entry = the copied code at guest RAM base; stack top = the window's end (16-aligned by the
    // 2 MiB size). `ram_end` is the *exclusive* end, but a full-descending push lands at `ram_end-16`
    // (still in-window), and the trivial guest touches neither the stack nor any data — so this is
    // correct-and-cosmetic (Arc-4 review, below-bar). SP_EL1 is set to a valid in-window address by
    // convention.
    (ram_start as u64, ram_end as u64)
}

/// Build the minimal Stage-2 tables identity-mapping the 2 MiB block that contains guest RAM, and
/// return the `VTTBR_EL2` value (L1 table PA | VMID).
fn build_stage2() -> u64 {
    let l1 = STAGE2_L1.0.get();
    let l2 = STAGE2_L2.0.get();
    let l1_pa = l1 as *const u8 as u64;
    let l2_pa = l2 as *const u8 as u64;

    // Guest RAM base as a plain address for index arithmetic; no dereference.
    let gpa = core::ptr::addr_of!(__guest_ram_start) as u64;
    // 39-bit IPA, start level 1: L1 indexes IPA[38:30] (1 GiB), L2 indexes IPA[29:21] (2 MiB).
    let idx1 = ((gpa >> 30) & 0x1ff) as usize;
    let idx2 = ((gpa >> 21) & 0x1ff) as usize;

    // SAFETY: single-CPU, one-time initialization before Stage-2 is enabled; the tables are 4 KiB
    // aligned (`#[repr(align(4096))]`) and 512 entries, so both indices are in range. Identity map:
    // the 2 MiB block's output address is the guest RAM base (2 MiB-aligned by the linker).
    unsafe {
        (*l1)[idx1] = (l2_pa & desc::TABLE_ADDR) | desc::TABLE;
        (*l2)[idx2] = (gpa & desc::BLOCK_ADDR) | desc::BLOCK_ATTRS;
    }

    l1_pa | (GUEST_VMID << 48)
}

/// Program Stage-2 and enable it: write `VTCR_EL2`/`VTTBR_EL2`, set `HCR_EL2.VM`, then invalidate
/// Stage-1&2 TLBs for the VMID and synchronize. The `tlbi`/`dsb`/`isb` are load-bearing on silicon
/// (a stale walk after changing `VTTBR_EL2`) and invisible-but-harmless under QEMU's TCG — the
/// per-mechanism QEMU-vs-metal line.
fn enable_stage2(vttbr: u64) {
    // SAFETY: all EL2-legal system registers. `HCR_EL2` is read-modified to add `VM` while keeping
    // the Arc-3 `RW` bit; Stage-2 affects only EL1&0 accesses, never EL2's own (the hypervisor
    // keeps running MMU-off/identity). `dsb`/`isb` make the new translation regime effective before
    // any guest access.
    unsafe {
        asm!(
            "msr vtcr_el2, {vtcr}",
            "msr vttbr_el2, {vttbr}",
            "mrs {tmp}, hcr_el2",
            "orr {tmp}, {tmp}, {vm}",
            "msr hcr_el2, {tmp}",
            "dsb ish",
            "tlbi vmalls12e1is",   // invalidate Stage-1&2 for the current VMID, inner-shareable
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

/// Initialize the guest's EL1 state: force `SCTLR_EL1` enables off (MMU/caches/alignment) so the
/// guest runs Stage-1-off from a known state (its reset value is architecturally UNKNOWN), and set
/// the guest stack pointer `SP_EL1`.
fn init_guest_el1(stack_top: u64) {
    // SAFETY: `SCTLR_EL1` and `SP_EL1` are EL1 registers writable from EL2; we clear M(0), A(1),
    // C(2), SA(3), SA0(4), I(12) via read-modify-write so the RES1 bits are preserved (rather than
    // trusting a revision-specific magic constant) and the guest's MMU, alignment-checks, and
    // caches are provably off. No memory effect.
    const SCTLR_EL1_ENABLES: u64 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 12);
    unsafe {
        asm!(
            "mrs {tmp}, sctlr_el1",
            "bic {tmp}, {tmp}, {en}",
            "msr sctlr_el1, {tmp}",
            "msr sp_el1, {sp}",
            en = in(reg) SCTLR_EL1_ENABLES,
            sp = in(reg) stack_top,
            tmp = out(reg) _,
            options(nomem, nostack),
        );
    }
}

/// Enter the guest at EL1 and never return: switch `SP_EL2` to the dedicated exception stack (so
/// trap handling runs there, cleanly separated from the abandoned boot stack), set `SPSR_EL2`, and
/// `eret`. `ELR_EL2` was already set via [`ArmVcpu::set_entry`]. This is the terminal step of
/// `run` — the boot stack is dead after this point, which is why the `SP_EL2` switch is safe.
fn enter_guest(exc_stack_top: u64) -> ! {
    // SAFETY: `SPSR_EL2` is RW at EL2; `mov sp, x` switches `SP_EL2` (we are at EL2, SPSel=1). After
    // the switch only `eret` runs, so no Rust stack access follows. `eret` is context-synchronizing
    // and transfers to EL1 at `ELR_EL2` with `SPSR_EL2`'s PSTATE. `options(noreturn)` because
    // control leaves EL2 and only re-enters via the vector table, never past this instruction.
    unsafe {
        asm!(
            "msr spsr_el2, {spsr}",
            "mov sp, {esp}",
            "dsb ish",
            "isb",
            "eret",
            spsr = in(reg) SPSR_EL2_GUEST,
            esp = in(reg) exc_stack_top,
            options(noreturn),
        );
    }
}

/// Read `ESR_EL2` and return its exception class (`EC`, bits [31:26]).
fn esr_el2_ec() -> u64 {
    let esr: u64;
    // SAFETY: `ESR_EL2` is RO at EL2; no memory effect.
    unsafe { asm!("mrs {e}, esr_el2", e = out(reg) esr, options(nomem, nostack, preserves_flags)) };
    (esr >> 26) & 0x3f
}

/// Route a raw guest hypercall (`nr`, `arg0`) through `hv-core`'s ABI-decode seam and the proven
/// integrated dispatch, returning the balance to hand back in `x0` (or [`HVCALL_REJECTED`]).
///
/// This is the whole seam in four lines: the guest's raw registers become a [`RawHypercall`],
/// [`Hypercall::decode`] (the fuzzed decoder) types it, the typed [`Hypercall`] is mapped to an
/// [`HvCall`] (the stand-in personality glue), and [`Hypervisor::dispatch`] — the proven brain —
/// services it. A decode rejection or a non-balance outcome collapses to the sentinel.
fn service_hypercall(hv: &mut Hypervisor, nr: u64, arg0: u64) -> u64 {
    let Ok(nr32) = u32::try_from(nr) else {
        return HVCALL_REJECTED;
    };
    let call = match Hypercall::decode(RawHypercall { nr: nr32, arg0 }) {
        Ok(Hypercall::Grant { amount }) => HvCall::CreditGrant { amount },
        Ok(Hypercall::Spend { amount }) => HvCall::CreditSpend { amount },
        Err(_) => return HVCALL_REJECTED,
    };
    match hv.dispatch(DOM0, call) {
        Ok(HvOutcome::Balance(b)) => b,
        _ => HVCALL_REJECTED,
    }
}

/// The Rust half of the guest synchronous-trap handler. Called from `__guest_sync_entry` with the
/// saved [`GuestFrame`]. For a serviceable hypercall it writes the result into the frame's `x0` and
/// returns (the trampoline restores + `eret`s → the guest resumes). For the terminal report it
/// witnesses the round trip and never returns (parks; under `selftest`, chains the Arc-2 fault-catch
/// first). A non-`HVC` synchronous exception is not expected in Arc 4 (a Stage-2 fault would be
/// Arc 5's negative test) — report it and halt.
///
/// # Safety
/// `frame` must be the valid `&mut GuestFrame` the trampoline saved on the exception stack.
#[no_mangle]
extern "C" fn handle_guest_sync(frame: *mut GuestFrame) {
    // SAFETY: `frame` is the save area the trampoline just wrote on the (valid, aligned) exception
    // stack; exclusive for the duration of this straight-line, non-nested handler.
    let frame = unsafe { &mut *frame };
    let mut uart = crate::uart();

    // Defensive re-entry guard: the guest handler must never be nested (see IN_GUEST_HANDLER).
    if IN_GUEST_HANDLER.swap(true, Ordering::Relaxed) {
        let _ = writeln!(
            uart,
            "baleen: guest handler re-entered (nested trap — must not happen); halting"
        );
        crate::park();
    }

    let ec = esr_el2_ec();
    if ec != 0x16 {
        // Not an HVC. In Arc 4 the guest only ever HVCs (it touches no unauthorized memory — that
        // is Arc 5). Anything else is a bug or an unexpected fault: report and halt.
        let _ = writeln!(
            uart,
            "baleen: guest sync trap with EC=0x{ec:02x} (not HVC); halting"
        );
        crate::park();
    }

    let nr = frame.x[0];
    let arg0 = frame.x[1];

    if nr == NR_GUEST_REPORT {
        report_and_finish(&mut uart, arg0);
    }

    // SAFETY: the global `Hypervisor` was built in `run` before the guest ran; single-CPU,
    // non-nested access.
    let hv = match unsafe { (*GUEST_HV.0.get()).as_mut() } {
        Some(hv) => hv,
        None => {
            let _ = writeln!(uart, "baleen: guest trap but no Hypervisor built; halting");
            crate::park();
        }
    };

    let result = service_hypercall(hv, nr, arg0);
    LAST_RESULT.store(result, Ordering::Relaxed);
    frame.x[0] = result; // hand the result back to the guest in x0
    let _ = writeln!(
        uart,
        "baleen: guest HVC serviced: nr={nr} arg={arg0} -> result={result}"
    );
    // Clear the re-entry guard: this is the resume path, so the next trap enters cleanly. (The
    // terminal/halt paths never return here — they park — so they need not clear it.)
    IN_GUEST_HANDLER.store(false, Ordering::Relaxed);
    // Return: the trampoline restores GPRs (with the updated x0) and `eret`s — the guest resumes at
    // the instruction after its `hvc`.
}

/// The terminal witness: the guest has echoed back the balance it observed. Assert it equals the
/// value the hypervisor last returned, print the round-trip marker, and finish (never returns).
/// Under `--features selftest`, additionally hard-assert and then chain the Arc-2 deliberate-fault
/// self-test so the vector/`ESR` decode is still exercised in the same boot.
fn report_and_finish(uart: &mut Pl011, echoed: u64) -> ! {
    let expected = LAST_RESULT.load(Ordering::Relaxed);
    let matched = echoed == expected && echoed == EXPECTED_BALANCE;
    if matched {
        // Printed ONLY on an exact match: genuine evidence the guest observed the serviced balance.
        let _ = writeln!(
            uart,
            "baleen: guest observed HvCall result={echoed} via HVC round-trip (trap-and-service confirmed)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: guest round-trip MISMATCH: echoed={echoed} expected={expected}; halting"
        );
    }

    #[cfg(feature = "selftest")]
    {
        if matched {
            let _ = writeln!(uart, "baleen: selftest: guest round-trip OK");
        } else {
            let _ = writeln!(uart, "baleen: selftest: guest round-trip FAIL");
        }
        // Chain the Arc-2 fault-catch: a deliberate BRK at EL2 (SPSel=1) vectors to slot 4
        // (cur_el_spx_sync), which the diagnostic handler catches and decodes (EC=0x3c). Keeps the
        // Arc-2 witness alive in the same selftest boot even though the guest path is terminal.
        let _ = writeln!(uart, "baleen: exception self-test — executing BRK #0");
        // SAFETY: `BRK` raises a synchronous exception taken to the current EL (EL2); the installed
        // handler reports and halts.
        unsafe { asm!("brk #0") };
        let _ = writeln!(uart, "baleen: BUG — returned from the BRK self-test");
    }

    crate::park();
}

/// Run the Arc-4 guest trap-and-service round trip, then park. Builds the guest `Hypervisor`, loads
/// the guest image, brings up the minimal Stage-2, initializes EL1 state, sets the guest entry via
/// the realized `VcpuOps`, and `eret`s into EL1. Everything after the `eret` happens in the trap
/// handler; this call never returns.
pub(crate) fn run(uart: &mut Pl011) -> ! {
    // SAFETY: single-CPU, one-time; no guest has run yet, so no handler is touching the cell.
    unsafe { *GUEST_HV.0.get() = Some(crate::build_hypervisor()) };

    let (entry, stack_top) = load_guest();
    let vttbr = build_stage2();
    enable_stage2(vttbr);
    init_guest_el1(stack_top);

    // Realize the entry through the fence: `VcpuOps::set_entry` writes `ELR_EL2`.
    {
        use hv_hal::VcpuOps;
        ArmVcpu.set_entry(entry);
    }

    let _ = writeln!(
        uart,
        "baleen: entering EL1 guest (entry=0x{entry:016x}, Stage-2 VM=1) — trap-and-service"
    );

    // Exception stack top from the linker; the boot stack is abandoned past this point.
    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    enter_guest(exc_stack_top);
}
