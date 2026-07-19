// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # The negative-isolation test — the proof touches reality (M4 Arc 5)
//!
//! Arc 4 stood up trap-and-service: a guest issues `HVC`, traps to EL2, and the proven brain serves
//! it. It ran behind a *single 2 MiB identity block* — **no isolation content**. Arc 5 (see
//! `docs/ROADMAP.md`, `docs/AUDIT-2-P2M-STAGE2.md`) is the payoff: the guest runs behind **real
//! AArch64 Stage-2 tables generated from the proven `hv-core` `p2m`** ([`crate::stage2`]), and a
//! guest that touches memory the model forbids is **faulted by the hardware** to EL2, where the
//! hypervisor decodes the fault and confirms it is exactly the denied access. The proof stops being
//! a claim about a model and becomes a claim about running code — QEMU is a sound oracle for exactly
//! this (`docs/QEMU-AND-METAL.md`: Stage-2 fault semantics, the *single most valuable test QEMU can
//! run*).
//!
//! ## What the guest witnesses — the full authorize/deny matrix, in one boot
//!
//! The model is driven ([`setup_model`]) into a real multi-domain memory configuration: a guest
//! domain `G` that owns a writable frame and a read-only frame, plus a *peer* `P` that owns two
//! frames and **grants one** of them (read-write) to `G`. [`crate::stage2::build_stage2_from_p2m`]
//! emits Stage-2 from exactly that `p2m`. The guest then runs a scripted sequence and the hypervisor
//! records the outcome of every access:
//!
//! | access | model says | hardware does | witnessed by |
//! |---|---|---|---|
//! | write+read own **writable** frame | allowed | succeeds | the readback == the sentinel |
//! | read own **read-only** frame | allowed | succeeds | the readback == the value the HV seeded |
//! | write **foreign granted** frame | allowed (grant) | succeeds | the HV reads it back via `GuestMemory` |
//! | **write** the read-only frame | denied | **permission fault** | `EC=0x24`, `DFSC`=perm, `WnR=1` |
//! | read **foreign un-granted** frame | denied | **translation fault** | `EC=0x24`, `DFSC`=translation |
//! | read an **unmapped** IPA | denied | **translation fault** | `EC=0x24`, `DFSC`=translation |
//! | read G's **own page-table** frame | denied | **translation fault** | write-xor-pagetable on metal |
//!
//! The positive + negative pair is the diamond: the emitted table **permits exactly what the model
//! authorizes and denies exactly what it does not** (Architecture Audit #2's "no more, no less").
//!
//! ## Resume-past-fault
//!
//! A data abort from the guest lands in the same vector slot as its `HVC` (slot 8 — lower-EL/AArch64
//! synchronous), so the Arc-4 GPR save/restore trampoline serves both; [`handle_guest_sync`] branches
//! on `ESR_EL2.EC`. For a probe fault (`EC=0x24`) it records the syndrome, **advances `ELR_EL2` past
//! the faulting instruction** (a data abort returns to the faulting instruction, unlike `HVC` whose
//! preferred return is the next one), and `eret`s — so a single guest run witnesses every deny in the
//! matrix, not just the first. An abort whose IPA is outside the guest's data region is a genuine bug
//! and halts loudly rather than resuming.
//!
//! ## Scope (honest)
//!
//! Arc 5 *refines* the proof — it is the first **isolation** content on the metal: the real tables
//! generated from the proven `p2m` actually fault an unauthorized access, and QEMU confirms it. It is
//! QEMU-sound for CPU-initiated Stage-2 faults; it says nothing about timing, weak-memory ordering,
//! or DMA/SMMU (`docs/QEMU-AND-METAL.md`), and it does not close the crate-wide EL2-MMU real-HW gap
//! (`docs/ARC-4-TRAP-AND-SERVICE.md`, "Real-hardware readiness") — that gap is orthogonal to the
//! guest Stage-2 work here and stays named-and-deferred. Superpage and a runtime execute-never fault
//! are audited by construction with their runtime witness deferred (see `docs/AUDIT-2-P2M-STAGE2.md`).
//!
//! ## Unsafe
//!
//! As Arc 4: system-register writes (`VTCR_EL2`/`VTTBR_EL2`/`HCR_EL2`/`SCTLR_EL1`/`ELR_EL2`/`SP_EL1`/
//! `SPSR_EL2`), the `eret`, the vector trampoline's GPR save/restore, and copying the guest image into
//! guest RAM. New this arc: reading the abort syndrome (`ESR_EL2`/`HPFAR_EL2`/`FAR_EL2`) and advancing
//! `ELR_EL2` to resume. Building the Stage-2 tables and the guest-memory accesses live in
//! [`crate::stage2`]. Each block carries its justification; globals live behind `UnsafeCell` (never
//! `static mut`), as in `stage2.rs`/`heap.rs`.

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use hv_core::grant::{Frame, GrantRef};
use hv_core::hypervisor::DomId;
use hv_core::p2m::{Mfn, PtLevel};
use hv_core::{HvCall, HvOutcome, Hypercall, Hypervisor, RawHypercall};

use hv_hal::GuestMemory;

use crate::pl011::Pl011;
use crate::stage2::{self, GuestMem};

// ─── the model configuration the test drives + witnesses ─────────────────────────────────────
//
// Domains: dom0 is the boot control domain (Live, may_create). It creates the guest `G` (dom1) and a
// peer `P` (dom2). Frames (model machine-frame numbers, `Mfn`): `G` owns its L1 page table plus a
// writable and a read-only data frame; `P` owns a frame it grants to `G` and one it never grants.

const DOM0: DomId = 0;
/// The guest under test — owns its own frames, holds a grant into one of the peer's.
const GUEST_DOM: DomId = 1;
/// The peer that owns the foreign frames (one granted to the guest, one withheld).
const PEER_DOM: DomId = 2;

const F_ROOT: Mfn = 1; // G's L1 page table (pinned; parent of the leaves)
const F_RW: Mfn = 2; // G owns — mapped writable (positive: read/write succeeds)
const F_RO: Mfn = 3; // G owns — mapped read-only (positive: read; negative: write faults)
const F_FGRANT: Mfn = 4; // P owns, granted RW to G — mapped (positive: authorized foreign write)
const F_FUNGRANT: Mfn = 5; // P owns, NOT granted — unmapped in G (negative: translation fault)
const F_HOLE: Mfn = 6; // never mapped — an unmapped IPA (negative: translation fault)

/// The high half of `stage2::DATA_IPA_BASE` (`0x8000`), for the guest's `movz #hi, lsl #16`.
const DATA_IPA_HI: u64 = stage2::DATA_IPA_BASE >> 16;
const OFF_RW: u64 = F_RW as u64 * stage2::FRAME_SIZE;
const OFF_RO: u64 = F_RO as u64 * stage2::FRAME_SIZE;
const OFF_FGRANT: u64 = F_FGRANT as u64 * stage2::FRAME_SIZE;
const OFF_FUNGRANT: u64 = F_FUNGRANT as u64 * stage2::FRAME_SIZE;
const OFF_HOLE: u64 = F_HOLE as u64 * stage2::FRAME_SIZE;
const OFF_ROOT: u64 = F_ROOT as u64 * stage2::FRAME_SIZE;

/// Sentinel the guest writes to its own writable frame (positive control; not any hypercall input).
const SENTINEL_RW: u64 = 0xBEEF;
/// Sentinel the guest writes to the granted foreign frame (positive control for cross-domain share).
const SENTINEL_FGRANT: u64 = 0xF00D;
/// The value the guest *attempts* to write to its read-only frame (must be denied — never lands).
const SENTINEL_BAD: u64 = 0xDEAD;
/// The value the hypervisor seeds into the read-only frame via `GuestMemory`; the guest reads it back
/// (a value it could only have if the read-only mapping resolves to the frame the HV wrote).
const RO_SEED: u64 = 0x5EED;

// The guest's hypercall vocabulary. `0`/`1` route through the real brain (Arc-4 regression); the
// `0xf*` numbers are metal-local diagnostics (outside `hv-core`'s decoder range) that report probe
// results; `0xff` is the terminal final report.
const NR_GRANT: u64 = 0;
const NR_SPEND: u64 = 1;
const NR_CREDIT_ECHO: u64 = 0xf0;
const NR_POS_RW: u64 = 0xf1;
const NR_POS_RO: u64 = 0xf2;
const NR_FINAL: u64 = 0xff;

/// Balance the guest observes and echoes (`grant 100`, `spend 30` → `70`) — the Arc-4 witness value.
const EXPECTED_BALANCE: u64 = 70;

/// Sentinel returned to the guest in `x0` when a routed hypercall is rejected.
const HVCALL_REJECTED: u64 = u64::MAX;

// ---------------------------------------------------------------------------------------------
// The guest program.
//
// Position-independent AArch64 (every instruction is a `mov`/`movz`/`movk` immediate, a load/store
// through a register-built address, an `hvc`, or a relative branch), copied verbatim into guest RAM
// and `eret`ed to. Addresses are built with `movz #hi,lsl#16; movk #off` from the SAME consts the
// Stage-2 builder uses, so the guest and the emitted table can never drift. Acts 1–4:
//   1. Arc-4 credit round-trip (regression): grant/spend/echo through the real dispatch.
//   2. positive controls: write+read the owned writable frame, read the seeded read-only frame,
//      write the granted foreign frame — all AUTHORIZED, all must succeed.
//   3. negatives: write the read-only frame (permission fault), read the un-granted peer frame, an
//      unmapped IPA, and G's own page-table frame as data (translation faults) — each traps to EL2,
//      is recorded, and is resumed past.
//   4. final report: terminal `HVC`; the hypervisor asserts the whole matrix.
// ---------------------------------------------------------------------------------------------
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .global __guest_tpl_start
__guest_tpl_start:
    // ── Act 1: Arc-4 trap-and-service regression (acts as the guest domain) ──
    mov     x0, #0                          // NR_GRANT
    mov     x1, #100
    hvc     #0                              // -> x0 = 100
    mov     x0, #1                          // NR_SPEND
    mov     x1, #30
    hvc     #0                              // -> x0 = 70
    mov     x1, x0                          // echo the observed balance (70)
    mov     x0, #{NR_CREDIT_ECHO}
    hvc     #0                              // HV asserts echoed==served; resumes

    // ── Act 2: positive controls — authorized accesses must SUCCEED ──
    // own writable frame: write a sentinel, read it back
    movz    x2, #{DATA_HI}, lsl #16
    movk    x2, #{OFF_RW}
    movz    x3, #{SENTINEL_RW}
    str     x3, [x2]
    ldr     x4, [x2]                        // x4 = readback (expect SENTINEL_RW)
    // own read-only frame: read the hypervisor-seeded value
    movz    x2, #{DATA_HI}, lsl #16
    movk    x2, #{OFF_RO}
    ldr     x5, [x2]                        // x5 = seeded value (expect RO_SEED)
    // foreign granted frame: authorized (read-write grant) write
    movz    x2, #{DATA_HI}, lsl #16
    movk    x2, #{OFF_FGRANT}
    movz    x6, #{SENTINEL_FGRANT}
    str     x6, [x2]
    // report the two readbacks
    mov     x0, #{NR_POS_RW}
    mov     x1, x4
    hvc     #0
    mov     x0, #{NR_POS_RO}
    mov     x1, x5
    hvc     #0

    // ── Act 3: negatives — each faults to EL2; the handler records + resumes past ──
    // write to the read-only frame -> permission fault
    movz    x2, #{DATA_HI}, lsl #16
    movk    x2, #{OFF_RO}
    movz    x3, #{SENTINEL_BAD}
    str     x3, [x2]
    // read the un-granted peer frame -> translation fault
    movz    x2, #{DATA_HI}, lsl #16
    movk    x2, #{OFF_FUNGRANT}
    ldr     x7, [x2]
    // read an unmapped IPA -> translation fault
    movz    x2, #{DATA_HI}, lsl #16
    movk    x2, #{OFF_HOLE}
    ldr     x8, [x2]
    // read G's OWN page-table frame as data -> translation fault (write-xor-pagetable on the metal:
    // a frame the model types as a page table is not a leaf, so it is unmapped and unreachable)
    movz    x2, #{DATA_HI}, lsl #16
    movk    x2, #{OFF_ROOT}
    ldr     x9, [x2]

    // ── Act 4: final report (terminal) ──
    mov     x0, #{NR_FINAL}
    hvc     #0
0:  wfe                                     // the final report handler is terminal
    b       0b
    .global __guest_tpl_end
__guest_tpl_end:
    "#,
    NR_CREDIT_ECHO = const NR_CREDIT_ECHO,
    NR_POS_RW = const NR_POS_RW,
    NR_POS_RO = const NR_POS_RO,
    NR_FINAL = const NR_FINAL,
    DATA_HI = const DATA_IPA_HI,
    OFF_RW = const OFF_RW,
    OFF_RO = const OFF_RO,
    OFF_FGRANT = const OFF_FGRANT,
    OFF_FUNGRANT = const OFF_FUNGRANT,
    OFF_HOLE = const OFF_HOLE,
    OFF_ROOT = const OFF_ROOT,
    SENTINEL_RW = const SENTINEL_RW,
    SENTINEL_FGRANT = const SENTINEL_FGRANT,
    SENTINEL_BAD = const SENTINEL_BAD,
);

// ─── Stage-2 enable parameters (the descriptor building lives in `stage2.rs`) ─────────────────

/// `VTCR_EL2` = `0x8002_3559`: 4 KiB granule, 39-bit IPA (T0SZ=25), start level 1 (SL0=0b01), Normal
/// WBWA Inner-Shareable table walks, 40-bit PS, RES1 bit 31. `DS=0` (bit 32 clear) so the classic
/// (non-LPA2) descriptor format the `stage2` encodings assume is in force. Unchanged from Arc 4.
const VTCR_EL2: u64 =
    (1 << 31) | (0b010 << 16) | (0b11 << 12) | (0b01 << 10) | (0b01 << 8) | (0b01 << 6) | 25;

/// `HCR_EL2.VM` — bit 0, enables Stage-2 for EL1&0. OR'd onto the Arc-3 `HCR_EL2` (RW=bit 31);
/// `FWB` (bit 46) stays 0 so the `stage2` `MemAttr=0b1111` Normal-WB encoding is in force.
const HCR_EL2_VM: u64 = 1 << 0;

// ─── global guest state ───────────────────────────────────────────────────────────────────────

struct HvCell(UnsafeCell<Option<Hypervisor>>);
// SAFETY: single boot CPU; the only writer is `run` (before any guest runs) plus the straight-line,
// interrupt-masked, non-nested trap handler. No concurrent access exists.
unsafe impl Sync for HvCell {}
static GUEST_HV: HvCell = HvCell(UnsafeCell::new(None));

/// The balance the hypervisor last returned to the guest (across trap invocations), so the credit
/// echo can assert the guest echoed back exactly what it was served.
static LAST_RESULT: AtomicU64 = AtomicU64::new(u64::MAX);

/// Re-entry guard: the guest handler must never nest (see Arc 4). Defensive — the architecture makes
/// slot 8 non-nesting — so it never fires; if it ever does, halt loudly.
static IN_GUEST_HANDLER: AtomicBool = AtomicBool::new(false);

/// Per-frame data-abort record: the `DFSC` of the fault taken on that model frame's IPA, or `0` for
/// no fault. The sentinel is sound because a `0` is never *scored as a denial*: `is_translation`
/// (`0x04..0x07`) and `is_permission` (`0x0D..0x0F`) both reject it — so a probe that never faulted
/// reads as "not denied" and fails the matrix. (`DFSC=0x00` is itself a valid code, an address-size
/// fault at level 0, but none of the probed IPAs — well inside the 39-bit IPA window — can raise one;
/// and even then a missed write is independently caught by the positive content read-back.)
/// Sized to the model's frame count so a frame index is always in range. It also bounds the
/// "guest data region" [`record_data_abort`] accepts, so it MUST cover every model frame — asserted
/// at compile time against [`crate::NUM_FRAMES`] so a future arc that grows the model can't silently
/// push a probeable frame past the fault array (which would halt-on-fault rather than record it).
const NFRAMES: usize = 8;
const _: () = assert!(NFRAMES >= crate::NUM_FRAMES);
static FAULT_DFSC: [AtomicU64; NFRAMES] = [const { AtomicU64::new(0) }; NFRAMES];
/// The `WnR` bit (write-not-read) of that frame's fault — `true` for a store, meaningful with `DFSC`.
static FAULT_WNR: [AtomicBool; NFRAMES] = [const { AtomicBool::new(false) }; NFRAMES];

/// The value the guest read back from its writable frame, reported at [`NR_POS_RW`].
static POS_RW: AtomicU64 = AtomicU64::new(u64::MAX);
/// The value the guest read back from its read-only frame, reported at [`NR_POS_RO`].
static POS_RO: AtomicU64 = AtomicU64::new(u64::MAX);
/// The credit balance the guest echoed, reported at [`NR_CREDIT_ECHO`].
static CREDIT_ECHO: AtomicU64 = AtomicU64::new(u64::MAX);

extern "C" {
    static __guest_tpl_start: u8;
    static __guest_tpl_end: u8;
    static __exc_stack_top: u8;
    static __guest_ram_start: u8;
    static __guest_ram_end: u8;
}

/// `SPSR_EL2` to `eret` into the guest: EL1h (`SP_EL1`), AArch64, `DAIF` masked. = `0x3C5`.
const SPSR_EL2_GUEST: u64 = 0b0101 | (0b1111 << 6);

/// The guest register frame the trampoline saves and restores around servicing: `x0..x30`. `x0` is
/// where the guest's hypercall number arrives and the result is written back; the rest are preserved
/// verbatim. FP/SIMD (`v0..v31`) is not framed — harmless for this register-only guest (Arc-4 review).
#[repr(C)]
pub struct GuestFrame {
    pub x: [u64; 31],
}

// The vector trampoline for a lower-EL/AArch64 synchronous exception (slot 8) — both the guest's
// `HVC` and its data aborts land here. It must NOT clobber a guest register before saving it, so it
// saves `x0..x30`, hands the frame pointer to the Rust handler, then restores (reloading the handler's
// update to `x0`) and `eret`s. `handle_guest_sync` returns to resume (past an `HVC`, or — after
// advancing `ELR_EL2` — past a faulting instruction) and never returns for the terminal report.
global_asm!(
    r#"
    .section .text
    .balign 0x40
    .global __guest_sync_entry
__guest_sync_entry:
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
    bl      handle_guest_sync
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

/// A minimal `hv_hal::VcpuOps` realized on ARM (Arc 4). `set_entry` writes `ELR_EL2`;
/// `inject_interrupt` is honestly deferred (no GIC yet).
struct ArmVcpu;

impl hv_hal::VcpuOps for ArmVcpu {
    fn inject_interrupt(&mut self, _vector: u8) {
        let mut uart = crate::uart();
        let _ = writeln!(
            uart,
            "baleen: VcpuOps::inject_interrupt is unrealized (no GIC until a later arc); halting"
        );
        crate::park();
    }

    fn set_entry(&mut self, entry: u64) {
        // SAFETY: `ELR_EL2` is RW at EL2; it holds the address the next `eret` returns to.
        unsafe { asm!("msr elr_el2, {e}", e = in(reg) entry, options(nomem, nostack)) };
    }
}

/// Copy the guest template into guest RAM and return `(entry, stack_top)` guest-physical addresses.
fn load_guest() -> (u64, u64) {
    let tpl_start = core::ptr::addr_of!(__guest_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest_tpl_end) as usize;
    let ram_start = core::ptr::addr_of!(__guest_ram_start) as usize;
    let ram_end = core::ptr::addr_of!(__guest_ram_end) as usize;
    let len = tpl_end - tpl_start;
    // SAFETY: source is the in-image template; destination is the start of the reserved guest RAM
    // window, far larger than the template. Non-overlapping distinct regions.
    unsafe {
        core::ptr::copy_nonoverlapping(tpl_start as *const u8, ram_start as *mut u8, len);
    }
    (ram_start as u64, ram_end as u64)
}

/// Program Stage-2 and enable it: write `VTCR_EL2`/`VTTBR_EL2`, set `HCR_EL2.VM`, then invalidate
/// Stage-1&2 TLBs for the VMID and synchronize. The `dsb`/`tlbi`/`isb` are load-bearing on silicon and
/// invisible-but-harmless under QEMU. The table is built (invalid→valid) *before* this runs, so no
/// break-before-make is needed. Unchanged from Arc 4.
fn enable_stage2(vttbr: u64) {
    // SAFETY: all EL2-legal system registers; `HCR_EL2` is read-modified to add `VM` while keeping
    // the Arc-3 `RW` bit. Stage-2 affects only EL1&0 (never EL2's own MMU-off/identity accesses).
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

/// Initialize the guest's EL1 state: force `SCTLR_EL1` enables off (MMU/caches/alignment) so the guest
/// runs Stage-1-off from a known state, and set the guest stack pointer `SP_EL1`. Unchanged from Arc 4.
fn init_guest_el1(stack_top: u64) {
    const SCTLR_EL1_ENABLES: u64 = (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4) | (1 << 12);
    // SAFETY: `SCTLR_EL1`/`SP_EL1` are EL1 registers writable from EL2; read-modify-write preserves
    // RES1 bits. No memory effect.
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

/// Enter the guest at EL1 and never return: switch `SP_EL2` to the dedicated exception stack, set
/// `SPSR_EL2`, and `eret`. `ELR_EL2` was already set via [`ArmVcpu::set_entry`]. Unchanged from Arc 4.
fn enter_guest(exc_stack_top: u64) -> ! {
    // SAFETY: `SPSR_EL2` is RW at EL2; `mov sp,x` switches `SP_EL2`. After the switch only `eret`
    // runs, so no Rust stack access follows. `eret` transfers to EL1 at `ELR_EL2` with `SPSR_EL2`.
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

/// Read `(ESR_EL2, HPFAR_EL2)` for a Stage-2 data abort. `ESR_EL2.ISS` carries `DFSC`/`WnR`;
/// `HPFAR_EL2` carries the faulting IPA (`FAR_EL2` would carry the guest VA, which with Stage-1 off
/// equals the IPA — `HPFAR_EL2` is the architectural IPA source for a Stage-2 fault).
fn read_esr_hpfar() -> (u64, u64) {
    let (esr, hpfar): (u64, u64);
    // SAFETY: both RO EL2 system registers, readable at EL2; no memory effect.
    unsafe {
        asm!(
            "mrs {0}, esr_el2",
            "mrs {1}, hpfar_el2",
            out(reg) esr,
            out(reg) hpfar,
            options(nomem, nostack, preserves_flags),
        );
    }
    (esr, hpfar)
}

/// The faulting IPA from `HPFAR_EL2`: `FIPA` is `HPFAR_EL2[43:4]` holding `IPA[47:12]`, so the address
/// is `(HPFAR_EL2 & mask) << 8` (bit 4 → bit 12). The in-page offset (`IPA[11:0]`) is not in `HPFAR`;
/// 4 KiB-aligned is all the per-frame test needs. (Blind-auditor-confirmed; see the audit.)
fn faulting_ipa(hpfar: u64) -> u64 {
    (hpfar & 0x0000_0fff_ffff_fff0) << 8
}

/// Advance `ELR_EL2` past the faulting instruction (a fixed 4-byte A64 instruction), so `eret` resumes
/// the guest at the *next* instruction rather than re-executing the faulting access. Unlike an `HVC`
/// (whose preferred return is already the next instruction), a data abort returns to the faulting one.
fn advance_elr_past_fault() {
    // SAFETY: `ELR_EL2` is RW at EL2; adding one instruction width is the architected resume-past-abort
    // for a synchronous exception we choose to skip. No memory effect.
    unsafe {
        asm!(
            "mrs {t}, elr_el2",
            "add {t}, {t}, #4",
            "msr elr_el2, {t}",
            t = out(reg) _,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Route a raw guest hypercall (`nr`, `arg0`) through `hv-core`'s ABI-decode seam and the proven
/// dispatch, acting as [`GUEST_DOM`], returning the balance to hand back in `x0` (or the sentinel).
/// The whole seam in four lines — the same as Arc 4, now for the guest domain rather than dom0.
fn service_hypercall(hv: &mut Hypervisor, nr: u64, arg0: u64) -> u64 {
    let Ok(nr32) = u32::try_from(nr) else {
        return HVCALL_REJECTED;
    };
    let call = match Hypercall::decode(RawHypercall { nr: nr32, arg0 }) {
        Ok(Hypercall::Grant { amount }) => HvCall::CreditGrant { amount },
        Ok(Hypercall::Spend { amount }) => HvCall::CreditSpend { amount },
        Err(_) => return HVCALL_REJECTED,
    };
    match hv.dispatch(GUEST_DOM, call) {
        Ok(HvOutcome::Balance(b)) => b,
        _ => HVCALL_REJECTED,
    }
}

/// The Rust half of the guest synchronous-trap handler, called from `__guest_sync_entry` with the
/// saved [`GuestFrame`]. Branches on `ESR_EL2.EC`: an `HVC` (`0x16`) is serviced or reported; a data
/// abort (`0x24`) is a probe — its syndrome is recorded and the guest is resumed past it; anything
/// else is unexpected and halts.
///
/// # Safety
/// `frame` must be the valid `&mut GuestFrame` the trampoline saved on the exception stack.
#[no_mangle]
extern "C" fn handle_guest_sync(frame: *mut GuestFrame) {
    // SAFETY: `frame` is the save area the trampoline just wrote on the valid, aligned exception
    // stack; exclusive for this straight-line, non-nested handler.
    let frame = unsafe { &mut *frame };
    let mut uart = crate::uart();

    // Defensive re-entry guard (see IN_GUEST_HANDLER): never fires; halts loudly if it ever does.
    if IN_GUEST_HANDLER.swap(true, Ordering::Relaxed) {
        let _ = writeln!(
            uart,
            "baleen: guest handler re-entered (nested trap — must not happen); halting"
        );
        crate::park();
    }

    match esr_el2_ec() {
        0x16 => service_hvc(frame, &mut uart), // returns to resume, or diverges on the final report
        0x24 => record_data_abort(&mut uart),  // records the syndrome + advances ELR to resume past
        ec => {
            let _ = writeln!(
                uart,
                "baleen: guest sync trap with unexpected EC=0x{ec:02x}; halting"
            );
            crate::park();
        }
    }

    // Resume path: clear the guard so the next trap enters cleanly. (The terminal/halt paths park and
    // never reach here.)
    IN_GUEST_HANDLER.store(false, Ordering::Relaxed);
}

/// Service an `HVC`: the Arc-4 credit round-trip (`0`/`1`) through the real dispatch, the diagnostic
/// probe-report calls (`0xf*`), or the terminal final report (`0xff`).
fn service_hvc(frame: &mut GuestFrame, uart: &mut Pl011) {
    let nr = frame.x[0];
    let arg0 = frame.x[1];

    match nr {
        NR_GRANT | NR_SPEND => {
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
            frame.x[0] = result;
            let _ = writeln!(
                uart,
                "baleen: guest HVC serviced: nr={nr} arg={arg0} -> result={result}"
            );
        }
        NR_CREDIT_ECHO => {
            let served = LAST_RESULT.load(Ordering::Relaxed);
            CREDIT_ECHO.store(arg0, Ordering::Relaxed);
            if arg0 == served && arg0 == EXPECTED_BALANCE {
                // Printed only on an exact match: the guest observed the *serviced* balance (70 is no
                // call's input) — the Arc-4 trap-and-service witness, preserved.
                let _ = writeln!(
                    uart,
                    "baleen: guest observed HvCall result={arg0} via HVC round-trip (trap-and-service confirmed)"
                );
            } else {
                let _ = writeln!(
                    uart,
                    "baleen: guest round-trip MISMATCH: echoed={arg0} expected={served}"
                );
            }
        }
        NR_POS_RW => POS_RW.store(arg0, Ordering::Relaxed),
        NR_POS_RO => POS_RO.store(arg0, Ordering::Relaxed),
        NR_FINAL => finish_isolation_test(uart), // -> !
        other => {
            let _ = writeln!(uart, "baleen: guest HVC unknown nr={other}; halting");
            crate::park();
        }
    }
}

/// Record a guest data abort (a negative-isolation probe): decode `DFSC`/`WnR`/faulting-IPA, stamp the
/// per-frame record, and advance `ELR_EL2` so the guest resumes past the faulting access. An abort
/// whose IPA is outside the guest's model-data region is a genuine bug (the guest's own code faulting,
/// say) and halts loudly rather than being silently resumed.
fn record_data_abort(uart: &mut Pl011) {
    let (esr, hpfar) = read_esr_hpfar();
    let dfsc = esr & 0x3f;
    let wnr = (esr >> 6) & 1 != 0;
    let ipa = faulting_ipa(hpfar);

    let base = stage2::DATA_IPA_BASE;
    let region = NFRAMES as u64 * stage2::FRAME_SIZE;
    if ipa < base || ipa >= base + region {
        let _ = writeln!(
            uart,
            "baleen: UNEXPECTED data abort at IPA=0x{ipa:016x} (outside guest data region) \
             DFSC=0x{dfsc:02x}; halting"
        );
        crate::park();
    }
    let frame_no = ((ipa - base) / stage2::FRAME_SIZE) as usize;
    FAULT_DFSC[frame_no].store(dfsc, Ordering::Relaxed);
    FAULT_WNR[frame_no].store(wnr, Ordering::Relaxed);
    advance_elr_past_fault();
}

/// `true` if a `DFSC` is a **translation** fault (`0b0001LL`) — the IPA had no valid Stage-2 leaf.
fn is_translation(dfsc: u64) -> bool {
    dfsc & 0x3c == 0x04
}
/// `true` if a `DFSC` is a **permission** fault (`0b0011LL`) — mapped but the access exceeded `S2AP`.
fn is_permission(dfsc: u64) -> bool {
    dfsc & 0x3c == 0x0c
}

/// The terminal witness: assert the whole authorize/deny matrix and report, then finish (never
/// returns). Positive controls are read back (two from the guest's report, two the hypervisor reads
/// from guest memory via the realized `GuestMemory`); negatives are read from the per-frame fault
/// records. Under `--features selftest` it chains the Arc-2 deliberate-fault self-test so the vector /
/// `ESR` decode is still exercised in the same boot.
fn finish_isolation_test(uart: &mut Pl011) -> ! {
    // ── positive controls ──
    let credit = CREDIT_ECHO.load(Ordering::Relaxed);
    let rw_readback = POS_RW.load(Ordering::Relaxed);
    let ro_readback = POS_RO.load(Ordering::Relaxed);
    // The hypervisor reads the guest's writable and foreign-granted frames back through the fence, to
    // confirm the guest's authorized writes actually landed at the frames the model authorized.
    let rw_mem = read_frame(F_RW);
    let fgrant_mem = read_frame(F_FGRANT);

    let credit_ok = credit == EXPECTED_BALANCE;
    let rw_ok = rw_readback == SENTINEL_RW && rw_mem == SENTINEL_RW;
    let ro_ok = ro_readback == RO_SEED;
    let fgrant_ok = fgrant_mem == SENTINEL_FGRANT;
    let positive_ok = credit_ok && rw_ok && ro_ok && fgrant_ok;

    if positive_ok {
        let _ = writeln!(
            uart,
            "baleen: isolation positive OK: rw=0x{rw_readback:x} ro=0x{ro_readback:x} \
             fgrant=0x{fgrant_mem:x} (authorized accesses succeeded)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: isolation positive FAIL: credit={credit} rw={rw_readback:#x}/{rw_mem:#x} \
             ro={ro_readback:#x} fgrant={fgrant_mem:#x}"
        );
    }

    // ── negative controls ──
    let ro_dfsc = FAULT_DFSC[F_RO as usize].load(Ordering::Relaxed);
    let ro_wnr = FAULT_WNR[F_RO as usize].load(Ordering::Relaxed);
    let fungrant_dfsc = FAULT_DFSC[F_FUNGRANT as usize].load(Ordering::Relaxed);
    let hole_dfsc = FAULT_DFSC[F_HOLE as usize].load(Ordering::Relaxed);
    let root_dfsc = FAULT_DFSC[F_ROOT as usize].load(Ordering::Relaxed);
    // The authorized frames must NOT have faulted.
    let rw_faulted = FAULT_DFSC[F_RW as usize].load(Ordering::Relaxed) != 0;
    let fgrant_faulted = FAULT_DFSC[F_FGRANT as usize].load(Ordering::Relaxed) != 0;

    // Each marker prints ONLY when the decoded fault is exactly the expected class — a witness produced
    // by the mechanism, not an unconditional line.
    let ro_write_denied = is_permission(ro_dfsc) && ro_wnr;
    if ro_write_denied {
        let _ = writeln!(
            uart,
            "baleen: isolation negative OK: RO write -> permission fault (DFSC=0x{ro_dfsc:02x} WnR=1) \
             at IPA=0x{:08x}",
            stage2::frame_ipa(F_RO)
        );
    }
    let fungrant_denied = is_translation(fungrant_dfsc);
    if fungrant_denied {
        let _ = writeln!(
            uart,
            "baleen: isolation negative OK: foreign-ungranted read -> translation fault \
             (DFSC=0x{fungrant_dfsc:02x}) at IPA=0x{:08x}",
            stage2::frame_ipa(F_FUNGRANT)
        );
    }
    let hole_denied = is_translation(hole_dfsc);
    if hole_denied {
        let _ = writeln!(
            uart,
            "baleen: isolation negative OK: unmapped read -> translation fault \
             (DFSC=0x{hole_dfsc:02x}) at IPA=0x{:08x}",
            stage2::frame_ipa(F_HOLE)
        );
    }
    // The write-xor-pagetable case (the blind refinement auditor's "canonical catastrophe"): G's own
    // frame typed as a page table is NOT a leaf, so it is unmapped and unreachable as data.
    let root_denied = is_translation(root_dfsc);
    if root_denied {
        let _ = writeln!(
            uart,
            "baleen: isolation negative OK: own-page-table read -> translation fault \
             (DFSC=0x{root_dfsc:02x}) at IPA=0x{:08x} (write-xor-pagetable enforced on the metal)",
            stage2::frame_ipa(F_ROOT)
        );
    }

    let negative_ok = ro_write_denied
        && fungrant_denied
        && hole_denied
        && root_denied
        && !rw_faulted
        && !fgrant_faulted;

    if positive_ok && negative_ok {
        // Printed ONLY when the whole matrix holds — the diamond: the real Stage-2 permits exactly what
        // the model authorizes and denies exactly what it does not.
        let _ = writeln!(
            uart,
            "baleen: NEGATIVE-ISOLATION TEST PASSED — real Stage-2 from p2m denies exactly what the model forbids"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: NEGATIVE-ISOLATION TEST FAILED (positive_ok={positive_ok} negative_ok={negative_ok} \
             ro_dfsc=0x{ro_dfsc:02x} fungrant_dfsc=0x{fungrant_dfsc:02x} hole_dfsc=0x{hole_dfsc:02x} \
             root_dfsc=0x{root_dfsc:02x})"
        );
    }

    #[cfg(feature = "selftest")]
    {
        if positive_ok && negative_ok {
            let _ = writeln!(uart, "baleen: selftest: isolation matrix OK");
        } else {
            let _ = writeln!(uart, "baleen: selftest: isolation matrix FAIL");
        }
        // Chain the Arc-2 fault-catch: a deliberate BRK at EL2 (SPSel=1) vectors to slot 4, which the
        // diagnostic handler catches and decodes (EC=0x3c) — keeps that witness alive in the same boot.
        let _ = writeln!(uart, "baleen: exception self-test — executing BRK #0");
        // SAFETY: `BRK` raises a synchronous exception taken to EL2; the installed handler reports+halts.
        unsafe { asm!("brk #0") };
        let _ = writeln!(uart, "baleen: BUG — returned from the BRK self-test");
    }

    crate::park();
}

/// Read a model frame's 8-byte contents through the realized `GuestMemory` (IPA → PA via the shared
/// `stage2` layout). Used to confirm the guest's authorized writes landed at the frame the model
/// authorized — a positive witness the guest itself cannot forge.
fn read_frame(m: Mfn) -> u64 {
    let mut buf = [0u8; 8];
    match GuestMem.read(stage2::frame_ipa(m), &mut buf) {
        Ok(()) => u64::from_le_bytes(buf),
        Err(_) => u64::MAX,
    }
}

/// Drive the proven model into the multi-domain memory configuration the test exercises, entirely
/// through the real [`Hypervisor::dispatch`] — so the Stage-2 the metal then emits is a translation of
/// state the *proven transitions* produced, not a hand-built table. Every step must succeed; a failure
/// is a bug in the setup (not the isolation property) and halts loudly.
fn setup_model(hv: &mut Hypervisor, uart: &mut Pl011) {
    // dom0 creates the guest (dom1) and the peer (dom2). Neither gets the creation capability.
    expect(
        hv,
        DOM0,
        HvCall::DomainCreate {
            target: GUEST_DOM,
            may_create: false,
        },
        "create guest",
        uart,
    );
    expect(
        hv,
        DOM0,
        HvCall::DomainCreate {
            target: PEER_DOM,
            may_create: false,
        },
        "create peer",
        uart,
    );

    // The guest allocates its L1 page table and its two data frames, and pins the table.
    expect(
        hv,
        GUEST_DOM,
        HvCall::P2mAllocate { mfn: F_ROOT },
        "alloc root",
        uart,
    );
    expect(
        hv,
        GUEST_DOM,
        HvCall::P2mAllocate { mfn: F_RW },
        "alloc rw",
        uart,
    );
    expect(
        hv,
        GUEST_DOM,
        HvCall::P2mAllocate { mfn: F_RO },
        "alloc ro",
        uart,
    );
    expect(
        hv,
        GUEST_DOM,
        HvCall::P2mPin {
            mfn: F_ROOT,
            level: PtLevel::L1,
        },
        "pin root",
        uart,
    );

    // The peer allocates its two frames and grants ONE of them read-write to the guest.
    expect(
        hv,
        PEER_DOM,
        HvCall::P2mAllocate { mfn: F_FGRANT },
        "alloc fgrant",
        uart,
    );
    expect(
        hv,
        PEER_DOM,
        HvCall::P2mAllocate { mfn: F_FUNGRANT },
        "alloc fungrant",
        uart,
    );
    expect(
        hv,
        PEER_DOM,
        HvCall::GrantAccess {
            gref: 0 as GrantRef,
            grantee: GUEST_DOM,
            frame: F_FGRANT as Frame,
            readonly: false,
        },
        "grant fgrant",
        uart,
    );

    // The guest links its leaves: its own writable frame, its own read-only frame, and the foreign
    // frame the peer granted (authorized by that grant at the p2m↔grant seam).
    expect(
        hv,
        GUEST_DOM,
        HvCall::P2mLink {
            parent: F_ROOT,
            slot: 0,
            child: F_RW,
            writable: true,
            leaf: true,
        },
        "link rw",
        uart,
    );
    expect(
        hv,
        GUEST_DOM,
        HvCall::P2mLink {
            parent: F_ROOT,
            slot: 1,
            child: F_RO,
            writable: false,
            leaf: true,
        },
        "link ro",
        uart,
    );
    expect(
        hv,
        GUEST_DOM,
        HvCall::P2mLink {
            parent: F_ROOT,
            slot: 2,
            child: F_FGRANT,
            writable: true,
            leaf: true,
        },
        "link fgrant",
        uart,
    );
}

/// Dispatch one setup hypercall and require it to succeed; halt loudly on any rejection.
fn expect(hv: &mut Hypervisor, caller: DomId, call: HvCall, what: &str, uart: &mut Pl011) {
    if let Err(e) = hv.dispatch(caller, call) {
        let _ = writeln!(uart, "baleen: model setup '{what}' failed: {e:?}; halting");
        crate::park();
    }
}

/// Run the Arc-5 negative-isolation test, then park. Build the guest `Hypervisor`, drive the model
/// into the test configuration, emit real Stage-2 from that `p2m`, seed the read-only frame through the
/// fence, load + enter the guest. Everything after the `eret` happens in the trap handler; this never
/// returns.
pub(crate) fn run(uart: &mut Pl011) -> ! {
    // SAFETY: single-CPU, one-time; no guest has run yet, so no handler is touching the cell.
    unsafe { *GUEST_HV.0.get() = Some(crate::build_hypervisor()) };
    // SAFETY: as above — exclusive access to build the model configuration before any guest runs.
    let hv = match unsafe { (*GUEST_HV.0.get()).as_mut() } {
        Some(hv) => hv,
        None => crate::park(),
    };

    setup_model(hv, uart);

    // Emit Stage-2 from the proven p2m (the refinement — the Audit #2 target).
    let vttbr = stage2::build_stage2_from_p2m(hv, GUEST_DOM);

    // Seed the read-only frame with a value the guest can only echo back if the RO mapping resolves to
    // the frame the hypervisor wrote — a positive witness the guest cannot forge. Through the fence.
    {
        let mut gm = GuestMem;
        if gm
            .write(stage2::frame_ipa(F_RO), &RO_SEED.to_le_bytes())
            .is_err()
        {
            let _ = writeln!(
                uart,
                "baleen: failed to seed the read-only guest frame; halting"
            );
            crate::park();
        }
    }

    let (entry, _stack_top) = load_guest();
    enable_stage2(vttbr);
    // The guest's stack top is the top of its identity-mapped image window (guest RAM end).
    let ram_end = core::ptr::addr_of!(__guest_ram_end) as u64;
    init_guest_el1(ram_end);

    {
        use hv_hal::VcpuOps;
        ArmVcpu.set_entry(entry);
    }

    let _ = writeln!(
        uart,
        "baleen: entering EL1 guest (entry=0x{entry:016x}, real Stage-2 from p2m) — negative-isolation test"
    );

    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    enter_guest(exc_stack_top);
}
