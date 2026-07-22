// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # Isolation, lifecycle, and the scheduler — live (M4 Arc 5 → M5 Arc 0 → M5 Arc 1)
//!
//! **M5 Arc 1 — the concurrent scheduler, live.** After the lifecycle phase, [`run`]'s chain reaches
//! [`begin_scheduler_phase3`]: two vCPUs of one domain time-slice on the single physical CPU, switched
//! by hv-core's **real** scheduler. On each cooperative yield ([`NR_YIELD`]) the metal saves the
//! running vCPU's full [`GuestContext`], drives `SchedPreempt(cur)` + `SchedRun(other)` through the
//! proven `Hypervisor::dispatch`, and restores the peer's context (via the trampoline frame, or
//! [`__enter_guest_ctx`] for a first dispatch). Each vCPU carries a private counter seeded to a
//! distinct base; both must end at their own base + N iff every switch preserved its state and the two
//! never crossed. The sched pillar is cashed by two model-level refusals: `SchedRun` onto the occupied
//! pCPU → `PcpuBusy` (exclusivity), onto a non-affine pCPU → `NotAffine` (affinity). Cooperative, not
//! preemptive (no timer/GIC yet — that is a later arc); one physical CPU (concurrency is temporal, not
//! SMP). `hv-core`/`hv-hal` untouched (refines). See `docs/ARC-1-M5-SCHEDULER.md`.
//!
//! **M5 Arc 0 — the lifecycle, live.** After the Arc-5 matrix (below) passes, [`run`]'s terminal
//! handler does not park: it drives the proven *lifecycle* through the real [`Hypervisor::dispatch`]
//! ([`begin_lifecycle_phase2`]). dom0 **destroys** the guest — the proven teardown releases its
//! frames and sweeps the peer's grant to it ([`hv_core`]'s `revoke_grants_to`, design-lesson #15) —
//! then **reborns** a fresh domain in the *same slot*. The reborn `G′` gets a fresh isolated address
//! space (positive) but provably inherits **nothing**: it cannot even *link* the frame the peer had
//! granted to the dead `G` (refused at the p2m↔grant seam, no grant), so Stage-2(G′) has no
//! descriptor for it and `G′`'s probe of it is **faulted by the hardware** — the confused-deputy
//! defense (`DeadDomainNotClean` + `DeadDomainReferenced` + ID-reuse), on the metal. This adds the
//! genuinely-new metal capability the milestone needs: a **re-enterable run loop + `DomainDestroy` +
//! Stage-2 re-emit for a reborn slot**. Honest scope: the proof guarantees no inherited *authority*;
//! frame-content scrubbing on reuse is a metal allocator obligation, named-and-deferred (see
//! `docs/ARC-0-M5-LIFECYCLE.md`; `G′` here overwrites its frame before reading, so its own content is
//! fresh regardless).
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
use hv_core::sched::SchedError;
use hv_core::{HvCall, HvError, HvOutcome, Hypercall, Hypervisor, RawHypercall};

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

// ─── M5 Arc 0: the lifecycle matrix (a second incarnation in the same slot) ───────────────────
//
// After the Arc-5 matrix passes, dom0 DESTROYS the guest (`DomainDestroy` — the proven teardown,
// including `revoke_grants_to` clearing the peer's grant to it) and REBORNS a fresh domain in the
// SAME slot (`DomainCreate`). The reborn `G′` gets a fresh, isolated address space (positive) but
// provably inherits NOTHING from the dead `G`: the peer's grant was swept, so `G′` cannot even
// *link* the ex-granted frame (refused at the p2m↔grant seam), and Stage-2(G′) therefore has no
// descriptor for it — so a `G′` probe of that frame is FAULTED by the hardware. The confused-deputy
// defense (design-lesson #15's inbound-reference sweep), live on the metal.

/// Phase-2 positive report: the value `G′` read back from its own fresh writable frame.
const NR_POS_RW2: u64 = 0xf3;
/// Phase-2 terminal report — the mirror of [`NR_FINAL`] for the reborn guest.
const NR_FINAL2: u64 = 0xfe;
/// Sentinel `G′` writes to (then reads back from) its fresh writable frame. Distinct from every
/// phase-1 sentinel and from any hypercall input, so a read-back proves `G′`'s own store landed —
/// and, written-before-read, it is fresh content (the reused machine frame's stale bytes are
/// overwritten; see the audit's content-scrub scope note).
const SENTINEL_RW2: u64 = 0xCAFE;

// ─── M5 Arc 1: the vCPU context switch + concurrent scheduler run-loop ─────────────────────────
//
// Two vCPUs (of one domain) time-slice on the single physical CPU, switched by hv-core's REAL
// scheduler: on each cooperative yield (`NR_YIELD`) the metal saves the running vCPU's full context
// ([`GuestContext`]: GPRs + SP_EL1 + ELR/SPSR + SCTLR_EL1), drives `SchedPreempt(cur)` +
// `SchedRun(other)` through the proven `Hypervisor::dispatch`, and restores the other vCPU's context.
// Each vCPU carries a private counter (seeded to a DISTINCT base) across the interleaving; both must
// arrive at base+SCHED_YIELDS iff every switch preserved its own state and the two never crossed.
// The sched pillar is cashed by two model-level refusals: `SchedRun` onto an occupied pCPU →
// `PcpuBusy` (exclusivity); onto a non-affine pCPU → `NotAffine` (affinity).

/// The scheduler guest's yield hypercall — cooperative preemption point (no timer/GIC yet).
const NR_YIELD: u64 = 0xf4;
/// The scheduler guest's terminal report — carries its across-yields counter (`x1`) and vCPU id (`x2`).
const NR_SCHED_FINAL: u64 = 0xfd;
/// The domain the scheduler vCPUs belong to.
const SCHED_DOM: DomId = 1;
/// The two vCPU indices (within [`SCHED_DOM`]) that time-slice.
const SCHED_VCPU_A: u32 = 0;
const SCHED_VCPU_B: u32 = 1;
/// The single physical CPU the vCPUs contend for.
const PCPU0: u32 = 0;
/// How many yields each vCPU performs; its counter must end at its base + this.
const SCHED_YIELDS: u64 = 4;
/// Distinct counter bases seeded into each vCPU's context, so a context cross-leak is detectable
/// (a value in the wrong hundreds would betray it) and the two vCPUs are un-forgeably distinguished.
const SCHED_BASE_A: u64 = 0x100;
const SCHED_BASE_B: u64 = 0x200;
/// Metal-side vCPU context slots (one per scheduler vCPU).
const NUM_VCPUS_METAL: usize = 2;

/// The single Stage-2 table set (of [`stage2::NUM_STAGE2_SETS`]) every single-domain phase uses —
/// Arc 0/5 isolation + lifecycle and Arc 1's scheduler (both vCPUs share one address space). VMID 1.
/// The Arc-2 concurrent-isolation phase is the only caller that uses a second set. Named so a reader
/// sees at a glance that these phases are deliberately single-set, not accidentally colliding.
const STAGE2_SET_SINGLE: usize = 0;

// ─── M5 Arc 2: concurrent INTER-domain isolation (VMID-tagged) ─────────────────────────────────────
//
// The spatial complement of Arc 1's temporal multiplexing. TWO domains (each one vCPU) time-slice on
// the single physical CPU under the SAME hv-core scheduler, but now each runs in its OWN Stage-2 —
// a distinct table set, tagged with a distinct VMID (set + 1) — and the switch installs the peer
// domain's VTTBR with NO `tlbi` (distinct VMIDs stop the two domains' TLB entries aliasing). Each
// domain owns a distinct machine frame (distinct `Mfn` → distinct host PA), mapped by its own Stage-2
// at a per-domain IPA; the isolation falls straight out of the per-domain p2m → per-domain Stage-2
// refinement (each set emits only leaves whose parent that domain owns), with no hand-built holes.
//
// Witnesses: (1) concurrent isolation — each domain FAULTS (translation) probing the IPA the OTHER
// domain's frame lives at; (2) no cross-corruption — after the full interleave each frame still holds
// its OWN sentinel (guest read-back + the HV reads it back through `GuestMemory`); (3) VMID-tagged /
// no-flush — the isolation holds despite no `tlbi` on the switch.

/// The two concurrently-scheduled domains (a fresh `Hypervisor` is built for this phase, so these reuse
/// the low ids). Each owns one page-table root and one writable data frame.
const ISO_DOM_A: DomId = 1;
const ISO_DOM_B: DomId = 2;

/// dom A's frames: its `L1` page table (pinned) and its writable data leaf.
const F_A_ROOT: Mfn = 1;
const F_A_DATA: Mfn = 2;
/// dom B's frames — DISTINCT `Mfn`s, hence distinct host PA (`frame_pa` is injective in `Mfn`), so the
/// two domains' data are physically disjoint, not merely table-separated.
const F_B_ROOT: Mfn = 3;
const F_B_DATA: Mfn = 4;

/// Each domain's Stage-2 table set (and thus VMID: set 0 → VMID 1, set 1 → VMID 2).
const STAGE2_SET_A: usize = 0;
const STAGE2_SET_B: usize = 1;

/// The un-forgeable sentinel each domain writes to its OWN frame — distinct per domain and from every
/// other sentinel/hypercall input, so a cross-domain corruption (a peer's value landing in one's frame)
/// or a mis-mapped read is immediately visible.
const SENTINEL_ISO_A: u64 = 0xA1A1;
const SENTINEL_ISO_B: u64 = 0xB2B2;

/// The concurrent-isolation guest's terminal report — carries its OWN-frame read-back (`x1`) and its
/// vCPU id (`x2`). Distinct from every other `NR_*` (outside `hv-core`'s decoder range).
const NR_ISO_FINAL: u64 = 0xfc;

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

// ---------------------------------------------------------------------------------------------
// The phase-2 (reborn `G′`) guest program (M5 Arc 0).
//
// Same position-independent style as phase 1, but a *different* configuration exercises it: `G′`
// owns a fresh writable frame (`F_RW`, re-allocated after the dead `G` released it) and holds NO
// grant to the peer's `F_FGRANT` (it was revoked at teardown). So:
//   1. positive: write a fresh sentinel to its own writable frame and read it back — must SUCCEED.
//   2. the ID-reuse negative: read the frame the peer had granted to the *dead* `G` — must FAULT
//      (translation), because `G′` inherited no grant and Stage-2(G′) has no descriptor for it.
//   3. terminal report.
// ---------------------------------------------------------------------------------------------
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .global __guest2_tpl_start
__guest2_tpl_start:
    // ── positive: own (fresh) writable frame — write a sentinel, read it back ──
    movz    x2, #{DATA_HI}, lsl #16
    movk    x2, #{OFF_RW}
    movz    x3, #{SENTINEL_RW2}
    str     x3, [x2]
    ldr     x4, [x2]                        // x4 = readback (expect SENTINEL_RW2)
    mov     x0, #{NR_POS_RW2}
    mov     x1, x4
    hvc     #0

    // ── ID-reuse negative: read the peer frame granted to the DEAD G -> translation fault ──
    movz    x2, #{DATA_HI}, lsl #16
    movk    x2, #{OFF_FGRANT}
    ldr     x5, [x2]                        // faults to EL2; handler records + resumes past

    // ── terminal report ──
    mov     x0, #{NR_FINAL2}
    hvc     #0
0:  wfe                                     // the reborn final report handler is terminal
    b       0b
    .global __guest2_tpl_end
__guest2_tpl_end:
    "#,
    NR_POS_RW2 = const NR_POS_RW2,
    NR_FINAL2 = const NR_FINAL2,
    DATA_HI = const DATA_IPA_HI,
    OFF_RW = const OFF_RW,
    OFF_FGRANT = const OFF_FGRANT,
    SENTINEL_RW2 = const SENTINEL_RW2,
);

// ---------------------------------------------------------------------------------------------
// The scheduler-test guest program (M5 Arc 1). Register-only (no memory access beyond its own PC),
// and BOTH vCPUs run this SAME code — they diverge only by the per-vCPU register state the metal
// seeds via `__enter_guest_ctx`: `x20` = counter (seeded to a distinct base), `x21` = yields
// remaining, `x22` = vCPU id. Each carries its counter across the interleaving and reports it, so a
// context cross-leak (a counter in the wrong hundreds) or a lost switch is caught.
// ---------------------------------------------------------------------------------------------
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .global __guest3_tpl_start
__guest3_tpl_start:
    // x20 = counter (seeded base), x21 = yields remaining (seeded), x22 = vCPU id (seeded)
1:  add     x20, x20, #1
    mov     x0, #{NR_YIELD}
    hvc     #0                             // cooperative yield → EL2 switches to the peer vCPU
    sub     x21, x21, #1
    cbnz    x21, 1b
    // final report: counter in x1, vCPU id in x2
    mov     x1, x20
    mov     x2, x22
    mov     x0, #{NR_SCHED_FINAL}
    hvc     #0
0:  wfe                                     // terminal
    b       0b
    .global __guest3_tpl_end
__guest3_tpl_end:
    "#,
    NR_YIELD = const NR_YIELD,
    NR_SCHED_FINAL = const NR_SCHED_FINAL,
);

// ---------------------------------------------------------------------------------------------
// The concurrent-inter-domain-isolation guest program (M5 Arc 2). BOTH domains' vCPUs run this SAME
// code from the shared code image; they diverge only by the per-vCPU register state the metal seeds:
//   x20 = my sentinel, x22 = my vCPU id, x23 = MINE ipa (my own data frame), x24 = PEER ipa (the IPA
//   the OTHER domain's frame lives at, which my Stage-2 does NOT map).
// It writes its sentinel to its own frame (authorized), yields so the peer runs (and writes ITS frame),
// reads its own frame back (must be unchanged — the peer's run didn't corrupt it), then probes the
// peer's IPA (must FAULT — its Stage-2 has no leaf there), and finally reports its own-frame read-back.
// ---------------------------------------------------------------------------------------------
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .global __guest4_tpl_start
__guest4_tpl_start:
    // x20 = my sentinel, x22 = vCPU id, x23 = MINE ipa, x24 = PEER ipa
    str     x20, [x23]                     // write my sentinel to MY frame (authorized RW leaf)
    mov     x0, #{NR_YIELD}
    hvc     #0                             // yield → the peer domain runs (writes its own frame), back
    ldr     x25, [x23]                     // read MY frame back — must still hold my sentinel
    ldr     x26, [x24]                     // probe the PEER's frame IPA → translation FAULT (recorded)
    // terminal report: x1 = my-frame read-back, x2 = my vCPU id
    mov     x1, x25
    mov     x2, x22
    mov     x0, #{NR_ISO_FINAL}
    hvc     #0
0:  wfe                                    // terminal
    b       0b
    .global __guest4_tpl_end
__guest4_tpl_end:
    "#,
    NR_YIELD = const NR_YIELD,
    NR_ISO_FINAL = const NR_ISO_FINAL,
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

/// The value the reborn `G′` read back from its fresh writable frame, reported at [`NR_POS_RW2`]
/// (M5 Arc 0, phase 2).
static POS_RW2: AtomicU64 = AtomicU64::new(u64::MAX);

/// M5 Arc 1: which metal vCPU slot is currently on the (single physical) CPU — the index into
/// [`VCPU_CTX`] whose context is live in the trampoline frame. Alternates on each yield.
static CUR_VCPU: AtomicU64 = AtomicU64::new(0);
/// M5 Arc 1: how many `NR_YIELD` context switches the metal has serviced across both vCPUs.
static YIELDS_HANDLED: AtomicU64 = AtomicU64::new(0);
/// M5 Arc 1: the final counter each scheduler vCPU reports at [`NR_SCHED_FINAL`] (indexed by vCPU).
static SCHED_REPORT: [AtomicU64; NUM_VCPUS_METAL] =
    [const { AtomicU64::new(u64::MAX) }; NUM_VCPUS_METAL];
/// M5 Arc 1: bitmask of which vCPUs have hit their terminal report; the whole test finishes when
/// both bits are set.
static SCHED_DONE: AtomicU64 = AtomicU64::new(0);

/// M5 Arc 2: each concurrent-isolation domain's read-back of its OWN data frame (reported at
/// [`NR_ISO_FINAL`], indexed by metal vCPU slot) — must equal that domain's sentinel (no cross-domain
/// corruption after the peer ran).
static ISO_READBACK: [AtomicU64; NUM_VCPUS_METAL] =
    [const { AtomicU64::new(u64::MAX) }; NUM_VCPUS_METAL];
/// M5 Arc 2: bitmask of which concurrent-isolation vCPUs have hit their terminal report; the phase
/// finishes when both bits are set.
static ISO_DONE: AtomicU64 = AtomicU64::new(0);

extern "C" {
    static __guest_tpl_start: u8;
    static __guest_tpl_end: u8;
    static __guest2_tpl_start: u8;
    static __guest2_tpl_end: u8;
    static __guest3_tpl_start: u8;
    static __guest3_tpl_end: u8;
    static __guest4_tpl_start: u8;
    static __guest4_tpl_end: u8;
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

/// A metal-side vCPU's full saved context (M5 Arc 1). The GPRs (`x0..x30`) live transiently in the
/// trampoline's on-stack [`GuestFrame`] between trap and `eret`; a *context switch* moves them (plus
/// the EL1/EL2 system state that is NOT in that frame) into this per-vCPU store so a different vCPU's
/// context can be loaded before `eret`. `hv-core`'s `RunState` stays abstract — this concrete
/// register/sysreg state is the metal's own, keeping the `hv-hal` fence architecture-neutral.
///
/// **Scope:** the FP/SIMD registers (`v0..v31`) are deliberately NOT part of the saved context — the
/// scheduler guests are integer-register-only. A future FP-using guest would need `v0..v31` added here
/// (and to `__enter_guest_ctx`), or two such guests would silently cross-leak FP state across a switch.
#[repr(C)]
#[derive(Clone, Copy)]
struct GuestContext {
    /// `x0..x30`, mirrored to/from the trampoline frame. (`repr(C)` fixes the field offsets the
    /// `__enter_guest_ctx` asm hard-codes: `x[i]`@`i*8`, `sp_el1`@248, `elr_el2`@256, `spsr_el2`@264,
    /// `sctlr_el1`@272.)
    x: [u64; 31],
    /// `SP_EL1` — the guest's stack pointer (per-vCPU; not in the trampoline frame).
    sp_el1: u64,
    /// `ELR_EL2` — where this vCPU resumes (its PC at the yield/preempt point).
    elr_el2: u64,
    /// `SPSR_EL2` — the saved processor state to restore on `eret`.
    spsr_el2: u64,
    /// `SCTLR_EL1` — the guest's EL1 system control (MMU/cache enables etc.).
    sctlr_el1: u64,
}

impl GuestContext {
    const ZERO: Self = Self {
        x: [0; 31],
        sp_el1: 0,
        elr_el2: 0,
        spsr_el2: 0,
        sctlr_el1: 0,
    };
}

// The `__enter_guest_ctx` asm hard-codes these field offsets; bind them to the struct so a future
// field reorder (or a non-`u64` insertion) can't silently desync the asm from the layout — one source
// of truth, checked at compile time (design-lesson #14c, the `const _` discipline).
const _: () = {
    assert!(core::mem::offset_of!(GuestContext, x) == 0);
    assert!(core::mem::offset_of!(GuestContext, sp_el1) == 248);
    assert!(core::mem::offset_of!(GuestContext, elr_el2) == 256);
    assert!(core::mem::offset_of!(GuestContext, spsr_el2) == 264);
    assert!(core::mem::offset_of!(GuestContext, sctlr_el1) == 272);
};

struct CtxCell(UnsafeCell<[GuestContext; NUM_VCPUS_METAL]>);
// SAFETY: single boot CPU; written/read only by the straight-line, non-nested guest trap handler
// (and phase-3 setup before any scheduler guest runs). No concurrent access. Same discipline as
// `GUEST_HV` and the `stage2` tables.
unsafe impl Sync for CtxCell {}
static VCPU_CTX: CtxCell = CtxCell(UnsafeCell::new([GuestContext::ZERO; NUM_VCPUS_METAL]));

/// Per-metal-vCPU-slot scheduling identity + address space (M5 Arc 1 unified for Arc 2). The register
/// state lives in [`GuestContext`] (asm-bound offsets); this is the state the *metal switch* needs but
/// the trampoline never touches: which hv-core `(dom, vcpu)` this slot drives the scheduler as, and the
/// VMID-tagged `VTTBR_EL2` to install (no flush) when the slot is switched in.
///
/// For the single-domain scheduler phase (Arc 1) both slots carry the SAME domain and the SAME
/// `vttbr`, so restoring the VTTBR on a switch is an identity write — the concurrent-isolation phase
/// (Arc 2) is the only place the two slots differ (distinct domain, distinct VMID-tagged VTTBR), which
/// is exactly the per-domain switch the arc proves.
#[derive(Clone, Copy)]
struct VcpuMeta {
    /// The hv-core domain this slot belongs to — the caller the scheduler ops dispatch as.
    dom: DomId,
    /// The vCPU index *within its domain* that hv-core admits/runs/preempts.
    vcpu: u32,
    /// The domain's VMID-tagged `VTTBR_EL2` (`L1` PA | VMID<<48), installed with NO `tlbi` on switch.
    vttbr: u64,
}

impl VcpuMeta {
    const ZERO: Self = Self {
        dom: 0,
        vcpu: 0,
        vttbr: 0,
    };
}

struct MetaCell(UnsafeCell<[VcpuMeta; NUM_VCPUS_METAL]>);
// SAFETY: single boot CPU; written only at phase setup (before any scheduler guest runs) and read by
// the straight-line, non-nested trap handler. No concurrent access. Same discipline as `VCPU_CTX`.
unsafe impl Sync for MetaCell {}
static VCPU_META: MetaCell = MetaCell(UnsafeCell::new([VcpuMeta::ZERO; NUM_VCPUS_METAL]));

/// Read a metal vCPU slot's scheduling metadata (M5 Arc 1/2).
fn vcpu_meta(slot: usize) -> VcpuMeta {
    // SAFETY: single-CPU, non-nested handler; the metadata was written at phase setup before any guest
    // ran. Exclusive read.
    unsafe { (*VCPU_META.0.get())[slot] }
}

/// Install a VMID-tagged `VTTBR_EL2` with **no TLB flush** (M5 Arc 2 — the headline property). Switching
/// the active Stage-2 between two domains needs no `tlbi` *because* the two domains' translations are
/// tagged with distinct VMIDs (`set_vmid(set) = set + 1`): a walk for one domain's VMID can never hit
/// the other's cached entries, so the stale entries the switch leaves behind are inert, not aliasing.
/// (Contrast Arc 0's *rebirth*, which REUSES a VMID for a different tenant and therefore MUST `tlbi` —
/// design-lesson #28f. Distinct VMIDs ⇒ no flush; reused VMID ⇒ flush.) The `isb` makes the register
/// write take effect before the trampoline's `eret` resumes the switched-in vCPU. VMID/TLB tagging is
/// TCG-invisible (QEMU models no TLB retention), so on QEMU isolation is witnessed through the *tables*
/// (VTTBR → distinct `L1` → distinct leaves → distinct host PA); the VMID-tag soundness is reasoned
/// (design-lesson #23; `docs/AUDIT-4-CONCURRENT-STAGE2.md`).
fn set_vttbr_no_flush(vttbr: u64) {
    // SAFETY: `VTTBR_EL2` is RW at EL2; it only redirects Stage-2 walks for EL1&0 (EL2 runs
    // MMU-off/identity, so this handler's own accesses are unaffected). No memory effect; no `tlbi`.
    unsafe {
        asm!(
            "msr vttbr_el2, {v}",
            "isb",
            v = in(reg) vttbr,
            options(nomem, nostack),
        );
    }
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

/// Copy the **phase-2** (reborn `G′`) guest template over the same guest RAM window (the dead `G`'s
/// code is gone) and return its `entry` guest-physical address (M5 Arc 0).
fn load_guest2() -> u64 {
    let tpl_start = core::ptr::addr_of!(__guest2_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest2_tpl_end) as usize;
    let ram_start = core::ptr::addr_of!(__guest_ram_start) as usize;
    let len = tpl_end - tpl_start;
    // SAFETY: as `load_guest` — in-image template source, reserved guest-RAM destination far larger
    // than the template, non-overlapping.
    unsafe {
        core::ptr::copy_nonoverlapping(tpl_start as *const u8, ram_start as *mut u8, len);
    }
    ram_start as u64
}

/// Copy the **phase-3** (scheduler-test) guest template into guest RAM and return its `entry`
/// guest-physical address (M5 Arc 1).
fn load_guest3() -> u64 {
    let tpl_start = core::ptr::addr_of!(__guest3_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest3_tpl_end) as usize;
    let ram_start = core::ptr::addr_of!(__guest_ram_start) as usize;
    let len = tpl_end - tpl_start;
    // SAFETY: as `load_guest` — in-image template source, reserved guest-RAM destination far larger
    // than the template, non-overlapping.
    unsafe {
        core::ptr::copy_nonoverlapping(tpl_start as *const u8, ram_start as *mut u8, len);
    }
    ram_start as u64
}

/// Copy the **phase-4** (concurrent-isolation) guest template into guest RAM and return its `entry`
/// guest-physical address (M5 Arc 2). BOTH domains run this one shared code image — the isolation
/// surface is the per-domain *data* frames, not the code (see the phase-4 setup's scope note).
fn load_guest4() -> u64 {
    let tpl_start = core::ptr::addr_of!(__guest4_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest4_tpl_end) as usize;
    let ram_start = core::ptr::addr_of!(__guest_ram_start) as usize;
    let len = tpl_end - tpl_start;
    // SAFETY: as `load_guest` — in-image template source, reserved guest-RAM destination far larger
    // than the template, non-overlapping.
    unsafe {
        core::ptr::copy_nonoverlapping(tpl_start as *const u8, ram_start as *mut u8, len);
    }
    ram_start as u64
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

// The initial vCPU dispatch (M5 Arc 1): load a seeded [`GuestContext`] into the real registers +
// system state and `eret` into it. Unlike [`enter_guest`] (which erets with whatever GPRs are live),
// this seeds `x0..x30` from the context, so the metal gives each vCPU its own private initial
// register state (counter base, id). Used for each vCPU's FIRST entry; later switches go through the
// trampoline frame (see [`handle_yield`]). Offsets mirror `GuestContext`'s `repr(C)` layout.
global_asm!(
    r#"
    .section .text
    .balign 0x40
    .global __enter_guest_ctx
__enter_guest_ctx:
    // x0 = &GuestContext, x1 = exc_stack_top
    mov     sp, x1                          // SP_EL2 (for future traps)
    ldr     x2, [x0, #248]
    msr     sp_el1, x2
    ldr     x2, [x0, #256]
    msr     elr_el2, x2
    ldr     x2, [x0, #264]
    msr     spsr_el2, x2
    ldr     x2, [x0, #272]
    msr     sctlr_el1, x2
    ldp     x2, x3,   [x0, #16]
    ldp     x4, x5,   [x0, #32]
    ldp     x6, x7,   [x0, #48]
    ldp     x8, x9,   [x0, #64]
    ldp     x10, x11, [x0, #80]
    ldp     x12, x13, [x0, #96]
    ldp     x14, x15, [x0, #112]
    ldp     x16, x17, [x0, #128]
    ldp     x18, x19, [x0, #144]
    ldp     x20, x21, [x0, #160]
    ldp     x22, x23, [x0, #176]
    ldp     x24, x25, [x0, #192]
    ldp     x26, x27, [x0, #208]
    ldp     x28, x29, [x0, #224]
    ldr     x30,      [x0, #240]
    ldr     x1,       [x0, #8]
    ldr     x0,       [x0, #0]              // x0 last — destroys the context pointer
    dsb     ish
    isb
    eret
    "#
);

extern "C" {
    /// Load `*ctx` into the registers/sysregs and `eret` into the vCPU. `ctx` must be a valid,
    /// aligned `GuestContext`; `exc_stack_top` becomes `SP_EL2`. Never returns (transfers to EL1).
    fn __enter_guest_ctx(ctx: *const GuestContext, exc_stack_top: u64) -> !;
}

/// Read the guest's per-vCPU system state that lives OUTSIDE the trampoline GPR frame — `SP_EL1`,
/// `ELR_EL2`, `SPSR_EL2`, `SCTLR_EL1` — for a context save (M5 Arc 1).
fn read_sysctx() -> (u64, u64, u64, u64) {
    let (sp_el1, elr, spsr, sctlr): (u64, u64, u64, u64);
    // SAFETY: all four are readable at EL2 (SP_EL1/SCTLR_EL1 are EL1 regs accessible from EL2). No
    // memory effect.
    unsafe {
        asm!(
            "mrs {0}, sp_el1",
            "mrs {1}, elr_el2",
            "mrs {2}, spsr_el2",
            "mrs {3}, sctlr_el1",
            out(reg) sp_el1,
            out(reg) elr,
            out(reg) spsr,
            out(reg) sctlr,
            options(nomem, nostack, preserves_flags),
        );
    }
    (sp_el1, elr, spsr, sctlr)
}

/// Write the guest's per-vCPU system state — the inverse of [`read_sysctx`] — for a context restore.
/// `ELR_EL2`/`SPSR_EL2` are consumed by the trampoline's terminal `eret`; `SP_EL1`/`SCTLR_EL1` are the
/// resumed vCPU's own EL1 state.
fn write_sysctx(sp_el1: u64, elr: u64, spsr: u64, sctlr: u64) {
    // SAFETY: all four are writable at EL2; the values come from a previously-saved [`GuestContext`].
    // No memory effect. The trampoline's `eret` (after this handler returns) reads back ELR/SPSR.
    unsafe {
        asm!(
            "msr sp_el1, {0}",
            "msr elr_el2, {1}",
            "msr spsr_el2, {2}",
            "msr sctlr_el1, {3}",
            in(reg) sp_el1,
            in(reg) elr,
            in(reg) spsr,
            in(reg) sctlr,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Save the running vCPU's context — GPRs from the trampoline `frame` plus its live system state —
/// into `VCPU_CTX[vcpu]` (M5 Arc 1).
fn save_context(vcpu: usize, frame: &GuestFrame) {
    let (sp_el1, elr, spsr, sctlr) = read_sysctx();
    // SAFETY: single-CPU, non-nested handler → exclusive access to the context store.
    let ctx = unsafe { &mut (*VCPU_CTX.0.get())[vcpu] };
    ctx.x = frame.x;
    ctx.sp_el1 = sp_el1;
    ctx.elr_el2 = elr;
    ctx.spsr_el2 = spsr;
    ctx.sctlr_el1 = sctlr;
}

/// Restore a vCPU's context — GPRs into the trampoline `frame` (so its `ldp`+`eret` resumes that
/// vCPU), its EL1/EL2 system state via `msr`, AND its domain's VMID-tagged Stage-2 (`VTTBR_EL2`, no
/// flush — M5 Arc 2). For the single-domain scheduler phase both slots carry the same VTTBR, so the
/// Stage-2 install is an identity write; for the concurrent-isolation phase it swaps to the peer
/// domain's address space.
fn restore_context(vcpu: usize, frame: &mut GuestFrame) {
    // SAFETY: as [`save_context`] — exclusive single-CPU access.
    let ctx = unsafe { (*VCPU_CTX.0.get())[vcpu] };
    frame.x = ctx.x;
    write_sysctx(ctx.sp_el1, ctx.elr_el2, ctx.spsr_el2, ctx.sctlr_el1);
    set_vttbr_no_flush(vcpu_meta(vcpu).vttbr);
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
        NR_FINAL => finish_isolation_test(uart), // -> ! (phase 1 terminal → drives phase 2)
        NR_POS_RW2 => POS_RW2.store(arg0, Ordering::Relaxed),
        NR_FINAL2 => finish_lifecycle_test(uart), // -> ! (phase 2 terminal → drives phase 3)
        NR_YIELD => handle_yield(frame, uart), // M5 Arc 1: switch to the peer vCPU (sched-driven)
        NR_SCHED_FINAL => handle_sched_final(frame, uart), // records + switches, or finishes
        NR_ISO_FINAL => handle_iso_final(frame, uart), // M5 Arc 2: records + switches, or finishes
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
    if positive_ok && negative_ok {
        let _ = writeln!(uart, "baleen: selftest: isolation matrix OK");
    } else {
        let _ = writeln!(uart, "baleen: selftest: isolation matrix FAIL");
    }

    // M5 Arc 0: with the Arc-5 baseline confirmed, drive the lifecycle — destroy the guest and reborn
    // a fresh domain in the same slot, then witness that it inherits nothing (never returns). If the
    // baseline itself failed, do NOT proceed on a broken foundation: park after reporting.
    if positive_ok && negative_ok {
        begin_lifecycle_phase2(uart);
    }
    crate::park();
}

/// **M5 Arc 0, phase 2 — the lifecycle, live.** Driven entirely through the real
/// [`Hypervisor::dispatch`] on the guest `Hypervisor` built in [`run`]:
///
/// 1. **Destroy** the guest (`DomainDestroy`) — the proven teardown releases its frames and, the
///    crux, `revoke_grants_to` clears the peer's grant to it (design-lesson #15's inbound sweep).
/// 2. **Clean-shell witness (model):** the slot is now `Dead` and owns none of its former frames.
/// 3. **Reborn** a fresh domain in the *same slot* (`DomainCreate`); it allocates a fresh root +
///    writable frame, pins, and links its own frame — a fresh, isolated address space.
/// 4. **ID-reuse witness (seam):** the reborn `G′` *cannot even link* the frame the peer had granted
///    to the dead `G` — `p2m_link` refuses it (no grant), so Stage-2(G′) has no descriptor for it.
/// 5. Re-emit Stage-2(G′) and re-enter the phase-2 guest, whose probe of that ex-granted frame is
///    then FAULTED by the hardware — the confused-deputy defense, live.
///
/// Never returns: it re-enters `G′`, whose terminal report ([`finish_lifecycle_test`]) parks.
fn begin_lifecycle_phase2(uart: &mut Pl011) -> ! {
    // SAFETY: single-CPU, non-nested; the global `Hypervisor` was built in `run` and this is the only
    // (straight-line) accessor now running — the guest is trapped at EL2, nothing else touches it.
    let hv = match unsafe { (*GUEST_HV.0.get()).as_mut() } {
        Some(hv) => hv,
        None => {
            let _ = writeln!(uart, "baleen: lifecycle: no Hypervisor built; halting");
            crate::park();
        }
    };

    // (1) Destroy the guest. `now` is a real generic-timer tick (the teardown uses it for runtime
    // accounting; any monotonic value is sound for the isolation witness).
    let now = {
        use hv_hal::TimeSource;
        crate::time::GenericTimer.now()
    };
    expect(
        hv,
        DOM0,
        HvCall::DomainDestroy {
            target: GUEST_DOM,
            now,
        },
        "destroy guest",
        uart,
    );

    // (2) Clean-shell witness: the dead slot is Dead and owns none of its former frames. Printed ONLY
    // when it actually holds — a witness produced by reading the proven model back, not a bare line.
    let dead = !hv.is_live(GUEST_DOM);
    let unowned = hv.p2m().owner_of(F_ROOT) != Some(GUEST_DOM)
        && hv.p2m().owner_of(F_RW) != Some(GUEST_DOM)
        && hv.p2m().owner_of(F_RO) != Some(GUEST_DOM);
    if dead && unowned {
        let _ = writeln!(
            uart,
            "baleen: lifecycle: guest destroyed — dead slot is a clean shell (Dead, owns no frames)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: lifecycle: teardown INCOMPLETE (dead={dead} unowned={unowned}); halting"
        );
        crate::park();
    }

    // (3) Reborn a fresh domain in the SAME slot, and give it a fresh isolated address space.
    expect(
        hv,
        DOM0,
        HvCall::DomainCreate {
            target: GUEST_DOM,
            may_create: false,
        },
        "reborn guest",
        uart,
    );
    expect(
        hv,
        GUEST_DOM,
        HvCall::P2mAllocate { mfn: F_ROOT },
        "reborn alloc root",
        uart,
    );
    expect(
        hv,
        GUEST_DOM,
        HvCall::P2mAllocate { mfn: F_RW },
        "reborn alloc rw",
        uart,
    );
    expect(
        hv,
        GUEST_DOM,
        HvCall::P2mPin {
            mfn: F_ROOT,
            level: PtLevel::L1,
        },
        "reborn pin root",
        uart,
    );
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
        "reborn link rw",
        uart,
    );

    // (4) The ID-reuse witness at the seam: `G′` must NOT be able to link the frame the peer granted
    // to the DEAD `G` — the grant was swept at teardown, so `p2m_link` refuses it. Printed ONLY when
    // the link is actually refused; a *success* here would be the confused-deputy bug, so halt loudly.
    match hv.dispatch(
        GUEST_DOM,
        HvCall::P2mLink {
            parent: F_ROOT,
            slot: 1,
            child: F_FGRANT,
            writable: true,
            leaf: true,
        },
    ) {
        // Pin the witness to the RIGHT cause: refused because `G′` holds no grant (`Unauthorized` at
        // the p2m↔grant seam), not any incidental refusal. A different `Err` would mean the frame is
        // unreachable for some OTHER reason (e.g. a future arc that also destroyed the peer would make
        // `owner_of(F_FGRANT)` None → a wrong-state refusal) — still denied, but not the property we
        // claim, so halt loudly rather than score it as the ID-reuse witness.
        Err(HvError::Unauthorized) => {
            let _ = writeln!(
                uart,
                "baleen: lifecycle: reborn slot could NOT link the destroyed grant \
                 (ID-reuse: no inherited authority)"
            );
        }
        Ok(_) => {
            let _ = writeln!(
                uart,
                "baleen: lifecycle: BUG — reborn slot linked the peer's revoked grant (confused deputy); halting"
            );
            crate::park();
        }
        Err(e) => {
            let _ = writeln!(
                uart,
                "baleen: lifecycle: reborn link refused for the WRONG reason ({e:?}) — not the no-grant witness; halting"
            );
            crate::park();
        }
    }

    // (5) Re-emit Stage-2 from `G′`'s p2m (maps its fresh writable frame; the ex-granted frame has no
    // leaf edge → no descriptor → a hole), and re-enter the phase-2 guest. The re-entry guard is
    // cleared here because we diverge into `eret` rather than returning through the trampoline.
    let vttbr = stage2::build_stage2_from_p2m(hv, GUEST_DOM, STAGE2_SET_SINGLE);
    // The per-frame fault records are behaviourally LIVE across the lifecycle boundary: phase 2 scores
    // its negatives from FAULT_DFSC, and a stale phase-1 fault on a frame phase 2 also probes would
    // manufacture a false witness. So reset them here — each incarnation's negatives are its own
    // (design-lesson #16: a live field resets on lifecycle exit). Phase 2 probes only F_FGRANT/F_RW
    // (both non-faulting positives in phase 1 → already 0), but resetting all keeps the reborn slot a
    // genuinely fresh page for any future phase-2 probe.
    for f in 0..NFRAMES {
        FAULT_DFSC[f].store(0, Ordering::Relaxed);
        FAULT_WNR[f].store(false, Ordering::Relaxed);
    }
    let entry = load_guest2();
    let ram_end = core::ptr::addr_of!(__guest_ram_end) as u64;
    enable_stage2(vttbr);
    init_guest_el1(ram_end);
    {
        use hv_hal::VcpuOps;
        ArmVcpu.set_entry(entry);
    }
    IN_GUEST_HANDLER.store(false, Ordering::Relaxed);
    let _ = writeln!(
        uart,
        "baleen: re-entering reborn EL1 guest (entry=0x{entry:016x}, fresh Stage-2) — lifecycle isolation test"
    );
    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    enter_guest(exc_stack_top);
}

/// **M5 Arc 0, phase 2 terminal.** Assert the lifecycle matrix: the reborn `G′` reached its own
/// fresh frame (positive) and was FAULTED probing the frame its dead predecessor was granted (the
/// ID-reuse negative). Prints the headline only when both hold. Under `--features selftest` it chains
/// the Arc-2 deliberate-fault self-test (moved here from phase 1 so it stays the boot's last act).
fn finish_lifecycle_test(uart: &mut Pl011) -> ! {
    // ── positive: `G′` reached its own fresh writable frame ──
    let rw2_readback = POS_RW2.load(Ordering::Relaxed);
    let rw2_mem = read_frame(F_RW); // the HV reads it back through the fence
    let pos_ok = rw2_readback == SENTINEL_RW2 && rw2_mem == SENTINEL_RW2;
    if pos_ok {
        let _ = writeln!(
            uart,
            "baleen: lifecycle positive OK: reborn guest reached its own fresh frame (rw=0x{rw2_mem:x})"
        );
    }

    // ── the ID-reuse negative: `G′` faulted probing the ex-granted frame ──
    let fgrant_dfsc = FAULT_DFSC[F_FGRANT as usize].load(Ordering::Relaxed);
    let inherit_denied = is_translation(fgrant_dfsc);
    // The fresh frame must NOT have faulted for `G′`.
    let rw2_faulted = FAULT_DFSC[F_RW as usize].load(Ordering::Relaxed) != 0;
    if inherit_denied {
        let _ = writeln!(
            uart,
            "baleen: lifecycle negative OK: reborn probe of the destroyed grant -> translation fault \
             (DFSC=0x{fgrant_dfsc:02x}) at IPA=0x{:08x} (no inherited reference reaches the peer frame)",
            stage2::frame_ipa(F_FGRANT)
        );
    }

    let lifecycle_ok = pos_ok && inherit_denied && !rw2_faulted;
    if lifecycle_ok {
        // Printed ONLY when the whole lifecycle matrix holds: a reborn slot gets a fresh isolated
        // address space and inherits NO authority from the domain that died in it.
        let _ = writeln!(
            uart,
            "baleen: LIFECYCLE ISOLATION TEST PASSED — a reborn slot inherits nothing (destroyed grant not re-reachable)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: LIFECYCLE ISOLATION TEST FAILED (pos_ok={pos_ok} inherit_denied={inherit_denied} \
             rw2_faulted={rw2_faulted} fgrant_dfsc=0x{fgrant_dfsc:02x})"
        );
    }

    // M5 Arc 1: with the lifecycle confirmed, drive phase 3 — the vCPU context switch + scheduler
    // run-loop (never returns). A broken lifecycle baseline parks rather than proceeding.
    if lifecycle_ok {
        begin_scheduler_phase3(uart);
    }
    crate::park();
}

/// The current generic-timer count, for stamping the sched ops' `now` (M5 Arc 1). `hv-core` owns no
/// clock, so the caller reads [`hv_hal::TimeSource`] and passes the tick in.
fn sched_now() -> u64 {
    use hv_hal::TimeSource;
    crate::time::GenericTimer.now()
}

/// Borrow the global scheduler `Hypervisor` (built in [`begin_scheduler_phase3`]); halts if unbuilt.
fn sched_hv(uart: &mut Pl011) -> &'static mut Hypervisor {
    // SAFETY: single-CPU, non-nested handler; the Hypervisor was built before any scheduler guest ran.
    match unsafe { (*GUEST_HV.0.get()).as_mut() } {
        Some(hv) => hv,
        None => {
            let _ = writeln!(uart, "baleen: scheduler: no Hypervisor built; halting");
            crate::park();
        }
    }
}

/// **M5 Arc 1 — the vCPU yield handler.** Save the running vCPU's context, drive hv-core's REAL
/// scheduler to preempt it and dispatch the peer (`SchedPreempt(cur)` + `SchedRun(other)` — the
/// pCPU-exclusivity invariant is maintained across the pair), then restore the peer's context so the
/// trampoline `eret`s into it. Returns to the trampoline.
fn handle_yield(frame: &mut GuestFrame, uart: &mut Pl011) {
    let cur = CUR_VCPU.load(Ordering::Relaxed) as usize;
    save_context(cur, frame);

    let next = 1 - cur;
    let (cur_m, next_m) = (vcpu_meta(cur), vcpu_meta(next));
    let now = sched_now();
    let hv = sched_hv(uart);
    // Preempt the running vCPU (as its owning domain) and dispatch the peer (as ITS owning domain — the
    // same domain when they share it [Arc 1], distinct domains under concurrent isolation [Arc 2]). The
    // pCPU-exclusivity invariant is maintained across the preempt→run pair; the peer's Stage-2 (its
    // VMID-tagged VTTBR) is installed by `restore_context` below, no flush.
    expect(
        hv,
        cur_m.dom,
        HvCall::SchedPreempt {
            vcpu: cur_m.vcpu,
            now,
        },
        "sched preempt",
        uart,
    );
    expect(
        hv,
        next_m.dom,
        HvCall::SchedRun {
            vcpu: next_m.vcpu,
            pcpu: PCPU0,
            now,
        },
        "sched run peer",
        uart,
    );

    CUR_VCPU.store(next as u64, Ordering::Relaxed);
    restore_context(next, frame);
    YIELDS_HANDLED.fetch_add(1, Ordering::Relaxed);
}

/// **M5 Arc 1 — a vCPU's terminal report.** Record its final counter (cross-checking its self-reported
/// id against the slot the metal switched to), and mark it done. When BOTH vCPUs have finished, assert
/// the scheduler matrix ([`finish_scheduler_test`]); otherwise retire this vCPU (`SchedOffline`) and
/// dispatch the peer so it can finish.
fn handle_sched_final(frame: &mut GuestFrame, uart: &mut Pl011) {
    let cur = CUR_VCPU.load(Ordering::Relaxed) as usize;
    let counter = frame.x[1];
    let reported_id = frame.x[2];
    // The guest's self-reported id (seeded x22) must match the slot the metal switched to — a
    // cross-check that the intended vCPU's context actually ran.
    if reported_id != cur as u64 {
        let _ = writeln!(
            uart,
            "baleen: scheduler: vCPU id mismatch (metal slot={cur}, guest reported={reported_id}); halting"
        );
        crate::park();
    }
    SCHED_REPORT[cur].store(counter, Ordering::Relaxed);
    let done = SCHED_DONE.fetch_or(1 << cur, Ordering::Relaxed) | (1 << cur);
    if done == (1u64 << NUM_VCPUS_METAL) - 1 {
        finish_scheduler_test(uart); // -> !
    }

    // The peer still has work: retire this vCPU and dispatch the peer, then resume it.
    retire_and_switch_to_peer(cur, frame, uart);
    // No YIELDS_HANDLED bump — this was a terminal report, not a yield.
}

/// After a vCPU hits its terminal report while the peer still has work: retire it (Running → Offline)
/// and dispatch the peer (Runnable → Running from its last preempt), then restore the peer's context so
/// the trampoline `eret`s into it. Each op is dispatched as the relevant vCPU's OWNING domain (from
/// [`vcpu_meta`]) — identical under Arc 1's single domain, distinct under Arc 2's concurrent isolation.
/// One shared tail for both terminals so the retire→switch sequence cannot drift between them.
fn retire_and_switch_to_peer(cur: usize, frame: &mut GuestFrame, uart: &mut Pl011) {
    let next = 1 - cur;
    let (cur_m, next_m) = (vcpu_meta(cur), vcpu_meta(next));
    let now = sched_now();
    let hv = sched_hv(uart);
    expect(
        hv,
        cur_m.dom,
        HvCall::SchedOffline {
            vcpu: cur_m.vcpu,
            now,
        },
        "sched offline finished vcpu",
        uart,
    );
    expect(
        hv,
        next_m.dom,
        HvCall::SchedRun {
            vcpu: next_m.vcpu,
            pcpu: PCPU0,
            now,
        },
        "sched run remaining vcpu",
        uart,
    );
    CUR_VCPU.store(next as u64, Ordering::Relaxed);
    restore_context(next, frame);
}

/// **M5 Arc 1, phase 3 — the concurrent scheduler run-loop.** Build a fresh `Hypervisor`, create the
/// scheduler domain, admit both vCPUs, and dispatch vCPU A. Witness the sched pillar's two refusals
/// (exclusivity: `SchedRun` onto the occupied pCPU → `PcpuBusy`; affinity: onto a non-affine pCPU →
/// `NotAffine`), then seed both vCPUs' contexts (distinct counter bases) and enter vCPU A via
/// [`__enter_guest_ctx`]. The two then time-slice on each yield ([`handle_yield`]). Never returns.
fn begin_scheduler_phase3(uart: &mut Pl011) -> ! {
    // A fresh Hypervisor: the lifecycle phase mutated the previous one. SAFETY: single-CPU, one-time
    // rebuild before any scheduler guest runs; no handler is touching the cell.
    unsafe { *GUEST_HV.0.get() = Some(crate::build_hypervisor()) };
    let hv = match unsafe { (*GUEST_HV.0.get()).as_mut() } {
        Some(hv) => hv,
        None => crate::park(),
    };

    // Both vCPUs belong to ONE domain (a single address space — concurrent isolation between two
    // DOMAINS is step 2b). Register-only guests → no data frames; Stage-2 is just the image block.
    expect(
        hv,
        DOM0,
        HvCall::DomainCreate {
            target: SCHED_DOM,
            may_create: false,
        },
        "create scheduler domain",
        uart,
    );

    let now = sched_now();
    // Admit both vCPUs (Offline → Runnable); dispatch A onto the pCPU (Runnable → Running).
    expect(
        hv,
        SCHED_DOM,
        HvCall::SchedAdmit { vcpu: SCHED_VCPU_A },
        "admit vcpu A",
        uart,
    );
    expect(
        hv,
        SCHED_DOM,
        HvCall::SchedAdmit { vcpu: SCHED_VCPU_B },
        "admit vcpu B",
        uart,
    );
    expect(
        hv,
        SCHED_DOM,
        HvCall::SchedRun {
            vcpu: SCHED_VCPU_A,
            pcpu: PCPU0,
            now,
        },
        "run vcpu A",
        uart,
    );

    // ── sched-pillar witness 1: pCPU exclusivity ── SchedRun B onto the pCPU A occupies → PcpuBusy.
    match hv.dispatch(
        SCHED_DOM,
        HvCall::SchedRun {
            vcpu: SCHED_VCPU_B,
            pcpu: PCPU0,
            now,
        },
    ) {
        Err(HvError::Sched(SchedError::PcpuBusy)) => {
            let _ = writeln!(
                uart,
                "baleen: scheduler exclusivity OK: SchedRun onto the occupied pCPU refused (PcpuBusy)"
            );
        }
        other => {
            let _ = writeln!(
                uart,
                "baleen: scheduler exclusivity BROKEN: expected PcpuBusy, got {other:?}; halting"
            );
            crate::park();
        }
    }

    // ── sched-pillar witness 2: affinity ── Probe onto a FREE pCPU that B's mask excludes, so the
    // refusal is affinity-ONLY (independent of occupancy AND of hv-core's affinity-vs-occupancy check
    // order): narrow B to {pCPU0} only, then SchedRun B onto pCPU1 (free, but off B's mask) → NotAffine.
    expect(
        hv,
        DOM0,
        HvCall::SchedSetAffinity {
            target: SCHED_DOM,
            vcpu: SCHED_VCPU_B,
            affinity: 0b01, // only pCPU 0 — excludes pCPU 1
        },
        "set B affinity (exclude pCPU1)",
        uart,
    );
    match hv.dispatch(
        SCHED_DOM,
        HvCall::SchedRun {
            vcpu: SCHED_VCPU_B,
            pcpu: 1, // a FREE pCPU, but off B's mask → the refusal can ONLY be affinity
            now,
        },
    ) {
        Err(HvError::Sched(SchedError::NotAffine)) => {
            let _ = writeln!(
                uart,
                "baleen: scheduler affinity OK: SchedRun onto a non-affine (free) pCPU refused (NotAffine)"
            );
        }
        other => {
            let _ = writeln!(
                uart,
                "baleen: scheduler affinity BROKEN: expected NotAffine, got {other:?}; halting"
            );
            crate::park();
        }
    }
    // Restore B's affinity so it may run on the pCPU in the loop.
    expect(
        hv,
        DOM0,
        HvCall::SchedSetAffinity {
            target: SCHED_DOM,
            vcpu: SCHED_VCPU_B,
            affinity: u64::MAX,
        },
        "restore B affinity",
        uart,
    );

    // Emit Stage-2 (one set, VMID 1 — both vCPUs share the domain's address space) and enable it.
    let vttbr = stage2::build_stage2_from_p2m(hv, SCHED_DOM, STAGE2_SET_SINGLE);
    let entry = load_guest3();
    let ram_end = core::ptr::addr_of!(__guest_ram_end) as u64;
    enable_stage2(vttbr);
    // Set the initial EL1 system state (MMU off, stack), then read it back to seed both contexts.
    init_guest_el1(ram_end);
    let (sp_el1, _elr, _spsr, sctlr) = read_sysctx();

    // Seed both vCPU contexts: same entry + system state, DISTINCT counter bases and ids. Both vCPUs
    // belong to ONE domain and share ONE address space, so both slots carry the SAME (dom, vttbr) — the
    // per-slot VTTBR restore on every switch is therefore an identity write here (the concurrent-
    // isolation phase is where the two slots' VTTBRs differ).
    // SAFETY: single-CPU, before any scheduler guest runs → exclusive access to the context + meta store.
    unsafe {
        let ctxs = &mut *VCPU_CTX.0.get();
        let metas = &mut *VCPU_META.0.get();
        for (i, base) in [SCHED_BASE_A, SCHED_BASE_B].into_iter().enumerate() {
            let c = &mut ctxs[i];
            *c = GuestContext::ZERO;
            c.x[20] = base; // counter (distinct seeded base)
            c.x[21] = SCHED_YIELDS; // yields remaining
            c.x[22] = i as u64; // vCPU id
            c.sp_el1 = sp_el1;
            c.elr_el2 = entry;
            c.spsr_el2 = SPSR_EL2_GUEST;
            c.sctlr_el1 = sctlr;
            metas[i] = VcpuMeta {
                dom: SCHED_DOM,
                vcpu: i as u32,
                vttbr, // both slots: the one domain's single VMID-1 Stage-2
            };
        }
    }

    CUR_VCPU.store(SCHED_VCPU_A as u64, Ordering::Relaxed);
    YIELDS_HANDLED.store(0, Ordering::Relaxed);
    SCHED_DONE.store(0, Ordering::Relaxed);
    IN_GUEST_HANDLER.store(false, Ordering::Relaxed);
    let _ = writeln!(
        uart,
        "baleen: scheduler phase — two vCPUs time-slice ({SCHED_YIELDS} yields each), hv-core sched drives the switch"
    );
    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    // SAFETY: VCPU_CTX[A] is a valid, seeded GuestContext; exc_stack_top is the dedicated EL2 stack.
    unsafe { __enter_guest_ctx(&(*VCPU_CTX.0.get())[SCHED_VCPU_A as usize], exc_stack_top) }
}

/// **M5 Arc 1, phase 3 terminal.** Assert the concurrent scheduler matrix: each vCPU's counter ended
/// at its own seeded base + `SCHED_YIELDS` (its private context was preserved across the interleaving,
/// with no cross-leak between the two), and the metal serviced exactly `2 * SCHED_YIELDS` switches.
/// Under `--features selftest` chains the Arc-2 deliberate-fault self-test (the boot's last act).
fn finish_scheduler_test(uart: &mut Pl011) -> ! {
    let a = SCHED_REPORT[SCHED_VCPU_A as usize].load(Ordering::Relaxed);
    let b = SCHED_REPORT[SCHED_VCPU_B as usize].load(Ordering::Relaxed);
    let handled = YIELDS_HANDLED.load(Ordering::Relaxed);
    let a_ok = a == SCHED_BASE_A + SCHED_YIELDS;
    let b_ok = b == SCHED_BASE_B + SCHED_YIELDS;
    let switches_ok = handled == 2 * SCHED_YIELDS;
    let sched_ok = a_ok && b_ok && switches_ok;
    if sched_ok {
        // Printed ONLY when both counters ended at their OWN base + SCHED_YIELDS: each vCPU's private
        // register state survived every context switch, and the two never crossed (a leak would land a
        // counter in the wrong hundreds).
        let _ = writeln!(
            uart,
            "baleen: SCHEDULER TEST PASSED — two vCPUs time-sliced, each context preserved \
             (A={a:#x}, B={b:#x}, {handled} switches)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: SCHEDULER TEST FAILED (A={a:#x} B={b:#x} switches={handled}; expected A={:#x} B={:#x} switches={})",
            SCHED_BASE_A + SCHED_YIELDS,
            SCHED_BASE_B + SCHED_YIELDS,
            2 * SCHED_YIELDS
        );
    }

    // M5 Arc 2: with the scheduler confirmed, drive phase 4 — concurrent INTER-domain isolation (two
    // domains, each its own VMID-tagged Stage-2, time-slicing under the same scheduler; each faults on
    // the peer's memory). Never returns (it ends the boot, chaining the selftest BRK as the last act).
    // A broken scheduler baseline parks rather than layering a fresh phase on it.
    if sched_ok {
        begin_concurrent_iso_phase4(uart);
    }
    crate::park();
}

/// **M5 Arc 2 — the concurrent-isolation terminal report handler.** Record this domain's read-back of
/// its OWN frame (cross-checking its self-reported id against the metal slot the switch selected), mark
/// it done, and either assert the isolation matrix (when both domains have finished) or retire this
/// vCPU and switch to the peer so it can finish. Mirrors [`handle_sched_final`]'s shape.
fn handle_iso_final(frame: &mut GuestFrame, uart: &mut Pl011) {
    let cur = CUR_VCPU.load(Ordering::Relaxed) as usize;
    let readback = frame.x[1];
    let reported_id = frame.x[2];
    // The guest's self-reported id (seeded x22) must match the metal slot the switch selected — the
    // cross-check that the intended domain's context actually ran (a leaked/wrong switch is caught).
    if reported_id != cur as u64 {
        let _ = writeln!(
            uart,
            "baleen: concurrent-iso: vCPU id mismatch (metal slot={cur}, guest reported={reported_id}); halting"
        );
        crate::park();
    }
    ISO_READBACK[cur].store(readback, Ordering::Relaxed);
    let done = ISO_DONE.fetch_or(1 << cur, Ordering::Relaxed) | (1 << cur);
    if done == (1u64 << NUM_VCPUS_METAL) - 1 {
        finish_concurrent_iso_test(uart); // -> !
    }
    // The peer domain still has work: retire this vCPU and switch to it.
    retire_and_switch_to_peer(cur, frame, uart);
}

/// Drive the proven model into the **two-domain** concurrent-isolation configuration, entirely through
/// the real [`Hypervisor::dispatch`] — so each domain's Stage-2 is a translation of state the proven
/// transitions produced. Each domain creates its own page-table root + one writable data frame (a
/// DISTINCT `Mfn` per domain → distinct host PA), pins the root, and links the data frame as a writable
/// leaf. Every step must succeed; a failure is a setup bug and halts loudly.
fn setup_concurrent_model(hv: &mut Hypervisor, uart: &mut Pl011) {
    // dom0 creates the two peer domains (neither gets the creation capability).
    expect(
        hv,
        DOM0,
        HvCall::DomainCreate {
            target: ISO_DOM_A,
            may_create: false,
        },
        "create iso dom A",
        uart,
    );
    expect(
        hv,
        DOM0,
        HvCall::DomainCreate {
            target: ISO_DOM_B,
            may_create: false,
        },
        "create iso dom B",
        uart,
    );

    // Each domain: allocate its own root page table + one writable data frame, pin the root as an L1
    // page table, and link the data frame as a writable leaf. Distinct Mfns per domain → distinct PA.
    for (dom, root, data) in [
        (ISO_DOM_A, F_A_ROOT, F_A_DATA),
        (ISO_DOM_B, F_B_ROOT, F_B_DATA),
    ] {
        expect(
            hv,
            dom,
            HvCall::P2mAllocate { mfn: root },
            "iso alloc root",
            uart,
        );
        expect(
            hv,
            dom,
            HvCall::P2mAllocate { mfn: data },
            "iso alloc data",
            uart,
        );
        expect(
            hv,
            dom,
            HvCall::P2mPin {
                mfn: root,
                level: PtLevel::L1,
            },
            "iso pin root",
            uart,
        );
        expect(
            hv,
            dom,
            HvCall::P2mLink {
                parent: root,
                slot: 0,
                child: data,
                writable: true,
                leaf: true,
            },
            "iso link data",
            uart,
        );
    }
}

/// **M5 Arc 2, phase 4 — the concurrent inter-domain isolation run-loop.** Build a fresh `Hypervisor`,
/// drive the two-domain model, emit EACH domain's Stage-2 into its OWN set (distinct VMID), admit both
/// domains' vCPUs, and dispatch dom A. Witness cross-domain pCPU exclusivity (dom B `SchedRun` onto dom
/// A's pCPU → `PcpuBusy`), then seed both vCPU contexts (distinct sentinel + MINE/PEER IPAs) and enter
/// dom A via [`__enter_guest_ctx`]. The two domains then time-slice on each yield, each in its own
/// VMID-tagged Stage-2 (the switch installs the peer's VTTBR with no `tlbi`). Never returns.
fn begin_concurrent_iso_phase4(uart: &mut Pl011) -> ! {
    // A fresh Hypervisor: the scheduler phase mutated the previous one. SAFETY: single-CPU, one-time
    // rebuild before any phase-4 guest runs; no handler is touching the cell.
    unsafe { *GUEST_HV.0.get() = Some(crate::build_hypervisor()) };
    let hv = match unsafe { (*GUEST_HV.0.get()).as_mut() } {
        Some(hv) => hv,
        None => crate::park(),
    };

    setup_concurrent_model(hv, uart);

    // Emit each domain's Stage-2 into its OWN set → distinct VMID-tagged VTTBR. Both sets are disjoint
    // storage, so both live simultaneously; the switch selects between them by VTTBR alone (no flush).
    // Load-bearing ordering: BOTH sets are built HERE, before the single `enable_stage2` below whose
    // `dsb ish` publishes every descriptor — so dom B's set (reached later only via the no-`tlbi`
    // `set_vttbr_no_flush` switch, which issues no barrier of its own) is globally observable before
    // its walker first runs. A set reached by a no-flush switch must be built before that covering dsb.
    let vttbr_a = stage2::build_stage2_from_p2m(hv, ISO_DOM_A, STAGE2_SET_A);
    let vttbr_b = stage2::build_stage2_from_p2m(hv, ISO_DOM_B, STAGE2_SET_B);

    let now = sched_now();
    // Admit each domain's single vCPU (vcpu 0 within its domain) and dispatch dom A onto the pCPU.
    expect(
        hv,
        ISO_DOM_A,
        HvCall::SchedAdmit { vcpu: 0 },
        "iso admit A",
        uart,
    );
    expect(
        hv,
        ISO_DOM_B,
        HvCall::SchedAdmit { vcpu: 0 },
        "iso admit B",
        uart,
    );
    expect(
        hv,
        ISO_DOM_A,
        HvCall::SchedRun {
            vcpu: 0,
            pcpu: PCPU0,
            now,
        },
        "iso run A",
        uart,
    );

    // ── cross-domain exclusivity witness ── dom B's SchedRun onto the pCPU dom A occupies → PcpuBusy.
    // Now genuinely CROSS-domain (two distinct domains contend for one physical CPU), a stronger form
    // of Arc 1's same-domain exclusivity probe.
    match hv.dispatch(
        ISO_DOM_B,
        HvCall::SchedRun {
            vcpu: 0,
            pcpu: PCPU0,
            now,
        },
    ) {
        Err(HvError::Sched(SchedError::PcpuBusy)) => {
            let _ = writeln!(
                uart,
                "baleen: cross-domain exclusivity OK: dom B SchedRun onto dom A's pCPU refused (PcpuBusy)"
            );
        }
        other => {
            let _ = writeln!(
                uart,
                "baleen: cross-domain exclusivity BROKEN: expected PcpuBusy, got {other:?}; halting"
            );
            crate::park();
        }
    }

    // Enable dom A's Stage-2 for the first entry; load the shared program; set the initial EL1 state and
    // read it back to seed both contexts. (Both domains run this ONE code image — see the scope note.)
    let entry = load_guest4();
    let ram_end = core::ptr::addr_of!(__guest_ram_end) as u64;
    enable_stage2(vttbr_a);
    init_guest_el1(ram_end);
    let (sp_el1, _elr, _spsr, sctlr) = read_sysctx();

    // Seed both vCPU contexts + metadata. Slot 0 = dom A, slot 1 = dom B. Each carries its own sentinel,
    // its own frame's IPA (MINE, x23) and the PEER domain's frame IPA (x24, which its Stage-2 does NOT
    // map → the cross-probe faults). The metadata carries each slot's domain + VMID-tagged VTTBR.
    //
    // Scope note (named, not swept): the two domains SHARE their read-execute code image (this one
    // register-only program, identity-mapped in both sets) as test infrastructure — they run identical
    // code and never write it (verified by inspection: only `str`/`ldr` to the seeded DATA IPAs, `hvc`,
    // `mov`, `b`; no stack use, no self-modification). The isolation surface under test is the per-domain
    // DATA frames (distinct Mfn → distinct PA → distinct per-VMID Stage-2 leaf). A production control
    // domain would give each domain a private code image (the real-Linux capstone arc); deferred.
    // SAFETY: single-CPU, before any phase-4 guest runs → exclusive access to the context + meta store.
    unsafe {
        let ctxs = &mut *VCPU_CTX.0.get();
        let metas = &mut *VCPU_META.0.get();
        let seeds = [
            (
                ISO_DOM_A,
                vttbr_a,
                SENTINEL_ISO_A,
                stage2::frame_ipa(F_A_DATA),
                stage2::frame_ipa(F_B_DATA),
            ),
            (
                ISO_DOM_B,
                vttbr_b,
                SENTINEL_ISO_B,
                stage2::frame_ipa(F_B_DATA),
                stage2::frame_ipa(F_A_DATA),
            ),
        ];
        for (i, (dom, vttbr, sentinel, mine, peer)) in seeds.into_iter().enumerate() {
            let c = &mut ctxs[i];
            *c = GuestContext::ZERO;
            c.x[20] = sentinel; // my sentinel
            c.x[22] = i as u64; // vCPU id (metal slot)
            c.x[23] = mine; // MINE ipa (my own data frame)
            c.x[24] = peer; // PEER ipa (the other domain's frame — my Stage-2 has no leaf here)
            c.sp_el1 = sp_el1;
            c.elr_el2 = entry;
            c.spsr_el2 = SPSR_EL2_GUEST;
            c.sctlr_el1 = sctlr;
            metas[i] = VcpuMeta {
                dom,
                vcpu: 0, // vcpu 0 within its own domain
                vttbr,
            };
        }
    }

    // Reset per-incarnation switch + fault state (design-lesson #16: a field a future incarnation reads
    // must reset at the boundary). Phase 4 scores its negatives from FAULT_DFSC, so a stale phase-1/2
    // fault on a frame index phase 4 also uses would manufacture a false witness.
    CUR_VCPU.store(0, Ordering::Relaxed);
    ISO_DONE.store(0, Ordering::Relaxed);
    for f in 0..NFRAMES {
        FAULT_DFSC[f].store(0, Ordering::Relaxed);
        FAULT_WNR[f].store(false, Ordering::Relaxed);
    }
    IN_GUEST_HANDLER.store(false, Ordering::Relaxed);

    let _ = writeln!(
        uart,
        "baleen: concurrent-isolation phase — two domains (VMID 1/2) time-slice, each in its own Stage-2 (no tlbi on switch)"
    );
    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    // SAFETY: VCPU_CTX[0] is a valid, seeded GuestContext for dom A; exc_stack_top is the EL2 stack.
    unsafe { __enter_guest_ctx(&(*VCPU_CTX.0.get())[0], exc_stack_top) }
}

/// **M5 Arc 2, phase 4 terminal.** Assert the concurrent inter-domain isolation matrix: (1) no
/// cross-corruption — each domain read its OWN sentinel back after the peer ran, confirmed by the HV
/// reading each frame back through `GuestMemory`; (2) isolation — each domain FAULTED (translation, a
/// read) probing the IPA the OTHER domain's frame lives at (its VMID-tagged Stage-2 has no leaf there).
/// The fault frame index is the discriminator (a fault at dom B's frame = dom A's cross-probe, and vice
/// versa). Under `--features selftest` chains the Arc-2 deliberate-fault self-test (the boot's last act).
fn finish_concurrent_iso_test(uart: &mut Pl011) -> ! {
    // ── no cross-corruption (positive) ── each domain kept its own sentinel; the HV confirms via the
    // fence (distinct host PA, so the peer's run could not have touched it).
    let a_rb = ISO_READBACK[0].load(Ordering::Relaxed);
    let b_rb = ISO_READBACK[1].load(Ordering::Relaxed);
    let a_mem = read_frame(F_A_DATA);
    let b_mem = read_frame(F_B_DATA);
    let no_corruption = a_rb == SENTINEL_ISO_A
        && b_rb == SENTINEL_ISO_B
        && a_mem == SENTINEL_ISO_A
        && b_mem == SENTINEL_ISO_B;
    if no_corruption {
        let _ = writeln!(
            uart,
            "baleen: concurrent no-corruption OK: each domain kept its own frame after the peer ran \
             (A=0x{a_mem:x}, B=0x{b_mem:x})"
        );
    }

    // ── isolation (negative) ── each domain faulted probing the other's frame IPA. FAULT_DFSC is
    // indexed by the faulting frame: dom A probed dom B's frame (F_B_DATA); dom B probed dom A's
    // (F_A_DATA). A cross-probe is a READ, so WnR must be false; the fault class must be translation
    // (no leaf), not permission — pinned per design-lesson #28d.
    //
    // Note (witness independence): a negative index is ALSO the peer's OWN frame — e.g. index F_B_DATA
    // is where dom B writes+reads its own sentinel. So `a_denied` alone is not independent of dom B's
    // health: a contrived break where B can't map its own frame would fault at F_B_DATA (a read) and
    // spuriously satisfy `a_denied`. It is load-bearing ONLY in conjunction with `no_corruption`:
    // whenever `no_corruption` holds, B's own accesses at F_B_DATA all SUCCEEDED (recording nothing
    // there), so the only fault possibly recorded at F_B_DATA is dom A's genuine cross-probe. The
    // `PASSED` conjunction below is what makes each negative genuine (surfaced by the false-green audit).
    let a_probe_dfsc = FAULT_DFSC[F_B_DATA as usize].load(Ordering::Relaxed);
    let b_probe_dfsc = FAULT_DFSC[F_A_DATA as usize].load(Ordering::Relaxed);
    let a_denied =
        is_translation(a_probe_dfsc) && !FAULT_WNR[F_B_DATA as usize].load(Ordering::Relaxed);
    let b_denied =
        is_translation(b_probe_dfsc) && !FAULT_WNR[F_A_DATA as usize].load(Ordering::Relaxed);
    if a_denied {
        let _ = writeln!(
            uart,
            "baleen: concurrent isolation OK: dom A probing dom B's frame -> translation fault \
             (DFSC=0x{a_probe_dfsc:02x}) at IPA=0x{:08x}",
            stage2::frame_ipa(F_B_DATA)
        );
    }
    if b_denied {
        let _ = writeln!(
            uart,
            "baleen: concurrent isolation OK: dom B probing dom A's frame -> translation fault \
             (DFSC=0x{b_probe_dfsc:02x}) at IPA=0x{:08x}",
            stage2::frame_ipa(F_A_DATA)
        );
    }

    let iso_ok = no_corruption && a_denied && b_denied;
    if iso_ok {
        // Printed ONLY when the whole matrix holds: two domains time-sliced in distinct VMID-tagged
        // Stage-2 with no flush between them, each reached its own memory and was faulted on the peer's.
        let _ = writeln!(
            uart,
            "baleen: CONCURRENT ISOLATION TEST PASSED — two domains (VMID 1/2) time-sliced in distinct \
             Stage-2, each faulted on the peer's memory, no cross-corruption, no tlbi on switch"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: CONCURRENT ISOLATION TEST FAILED (no_corruption={no_corruption} a_denied={a_denied} \
             b_denied={b_denied} a_rb=0x{a_rb:x} b_rb=0x{b_rb:x} a_dfsc=0x{a_probe_dfsc:02x} b_dfsc=0x{b_probe_dfsc:02x})"
        );
    }

    #[cfg(feature = "selftest")]
    {
        // Chain the Arc-2 fault-catch: a deliberate BRK at EL2 (SPSel=1) vectors to slot 4, which the
        // diagnostic handler catches and decodes (EC=0x3c) — keeps that witness alive in the same boot.
        // Moved here (from the scheduler terminal) so it stays the boot's LAST act.
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
    let vttbr = stage2::build_stage2_from_p2m(hv, GUEST_DOM, STAGE2_SET_SINGLE);

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
