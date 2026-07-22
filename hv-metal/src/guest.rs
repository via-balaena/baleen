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
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use hv_core::grant::{Frame, GrantRef};
use hv_core::hypervisor::DomId;
use hv_core::p2m::{Mfn, PtLevel};
use hv_core::sched::SchedError;
use hv_core::{HvCall, HvError, HvOutcome, Hypercall, Hypervisor, RawHypercall};

use hv_hal::GuestMemory;

use crate::gic;
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

// ─── M5 Arc 3: virtio-mmio console ─────────────────────────────────────────────────────────────────
//
// A synthetic guest drives a real virtio-mmio v2 console device (emulated in EL2 as dom0's backend).
// The guest's mmio accesses trap (the device window is unmapped in Stage-2) and are trap-and-emulated;
// the virtqueue frames it grants to dom0 are the isolation content — the ring IS a proven grant.

/// The domain running the virtio-console driver (a fresh `Hypervisor` is built for this phase).
const VIRTIO_DOM: DomId = 1;
/// The backend domain that services the device — `dom0`, the control domain and grantee of the ring.
const VIRTIO_BACKEND: DomId = 0;

// The guest's frames (model `Mfn`s). It owns a page-table root plus the two frames it GRANTS to dom0:
// the virtqueue frame (descriptor table + available ring + used ring) and the TX data buffer.
const F_VQ_ROOT: Mfn = 1; // the guest's L1 page table (pinned)
const F_VQ: Mfn = 2; // the split virtqueue (desc @ +0, avail @ +0x100, used @ +0x200)
const F_BUF: Mfn = 3; // the TX data buffer (granted RO to dom0)
const F_BUF_UNGRANTED: Mfn = 4; // a buffer the guest owns but does NOT grant (the negative — step 4)

// The driver lays the three rings out within F_VQ at desc @ +0, avail @ +0x100, used @ +0x200 (see the
// guest program), and programs those as the queue addresses; the backend reads the addresses back from
// the registers and is layout-agnostic, so the offsets live only in the guest asm.

/// The guest builds the ring/buffer IPAs from these (`movz DATA_HI, lsl#16; movk OFF`).
const VQ_FRAME_OFF: u64 = F_VQ as u64 * stage2::FRAME_SIZE; // 0x2000 → IPA 0x8000_2000
const BUF_FRAME_OFF: u64 = F_BUF as u64 * stage2::FRAME_SIZE; // 0x3000 → IPA 0x8000_3000
const UNGRANTED_FRAME_OFF: u64 = F_BUF_UNGRANTED as u64 * stage2::FRAME_SIZE; // 0x4000 → 0x8000_4000

/// The driver reports the four mmio identity registers it read (`x1`=Magic, `x2`=Version, `x3`=DeviceID,
/// `x4`=VendorID); the backend asserts them. A checkpoint (resumes), not terminal.
const NR_VIRTIO_ID: u64 = 0xfb;
/// The driver reports the negotiation result (`x1`=device features word 1, `x2`=Status read back after
/// FEATURES_OK); the backend asserts VERSION_1 was offered+accepted and FEATURES_OK stuck. Checkpoint.
const NR_VIRTIO_NEGOTIATED: u64 = 0xf9;
/// The virtio-console phase's terminal report — the backend asserts the whole matrix and finishes.
const NR_VIRTIO_FINAL: u64 = 0xfa;

/// The high half of [`crate::virtio::VIRTIO_MMIO_BASE`] (`0x0a00`), for the guest's `movz #hi, lsl#16`.
const VIRTIO_MMIO_HI: u64 = crate::virtio::VIRTIO_MMIO_BASE >> 16;

// ─── M5 Arc 4: virtio-blk + copy-on-write template storage ──────────────────────────────────────────
//
// Two synthetic guests drive a real virtio-blk device (DeviceID 2) over a descriptor CHAIN. The disk is
// a shared read-only template + a per-tenant copy-on-write overlay (see [`crate::blk`]). The diamond:
// a write hits the overlay, never the template; a second tenant reads the template pristine.

/// The domain running a virtio-blk driver (a fresh `Hypervisor` per phase; both tenant phases reuse it).
const BLK_DOM: DomId = 1;
/// The backend domain that services the block device — `dom0`, the grantee of the guest's ring/buffers.
const BLK_BACKEND: DomId = 0;
// The block backend reuses the Arc-3 grant gate `backend_authorize`, which names the (grantor, grantee)
// pair by the console's `VIRTIO_DOM`/`VIRTIO_BACKEND` constants. That is correct ONLY because the block
// phase uses the same DomIds — pin the coupling at compile time so a future arc that gives the block
// device distinct DomIds cannot silently mis-gate every access against the wrong grantor.
const _: () = assert!(BLK_DOM == VIRTIO_DOM && BLK_BACKEND == VIRTIO_BACKEND);

// The block guest's frames (model `Mfn`s): a page-table root, the virtqueue, the request header, the
// data+status I/O buffer, and (the negative) a buffer it owns but does NOT grant.
const F_BLK_ROOT: Mfn = 1; // the guest's L1 page table (pinned)
const F_BLK_VQ: Mfn = 2; // the split virtqueue (desc @ +0, avail @ +0x100, used @ +0x200) — granted RW
const F_BLK_HDR: Mfn = 3; // the virtio_blk_req header (device-readable) — granted RO
const F_BLK_IO: Mfn = 4; // data buffer @ +0 (512 B) + status byte @ +0x200 — granted RW (device-writable)
const F_BLK_UNGRANTED: Mfn = 5; // owned, NOT granted — a descriptor pointing here is the negative

/// The block guest builds the ring/buffer IPAs from these (`movz DATA_HI, lsl#16; movk OFF`).
const BLK_VQ_OFF: u64 = F_BLK_VQ as u64 * stage2::FRAME_SIZE; // 0x2000 → IPA 0x8000_2000
const BLK_HDR_OFF: u64 = F_BLK_HDR as u64 * stage2::FRAME_SIZE; // 0x3000 → IPA 0x8000_3000
const BLK_IO_OFF: u64 = F_BLK_IO as u64 * stage2::FRAME_SIZE; // 0x4000 → IPA 0x8000_4000
const BLK_UNGRANTED_OFF: u64 = F_BLK_UNGRANTED as u64 * stage2::FRAME_SIZE; // 0x5000 → 0x8000_5000
/// The status byte sits at +0x200 within the I/O frame (past the 512-byte data area).
const BLK_STATUS_OFF_IN_IO: u64 = 0x200;

/// The template sector 0 content — the shared golden image a clean read falls through to. A printable
/// marker so the backend's echo of a served read is a positive boot-test witness.
const BLK_TEMPLATE_MARKER: &[u8] = b"baleen-blk-template-sector-0-pristine\n";
/// The first-tenant write payload — MUST NOT ever appear on the console (it is confined to tenant 0's
/// overlay). A `FORBIDDEN_MARKERS` guard catches it if a write reaches the template or overlays alias.
const BLK_POISON_MARKER: &[u8] = b"POISON-blk-guest0-write-must-not-cross\n";

/// The driver reports the four virtio-mmio identity registers (`x1`=Magic..`x4`=VendorID); checkpoint.
const NR_BLK_ID: u64 = 0xe0;
/// The driver reports negotiation (`x1`=device features word 1, `x2`=Status readback); checkpoint.
const NR_BLK_NEGOTIATED: u64 = 0xe1;
/// The driver reports the first 8 bytes it read back from the (device-written) data buffer (`x1`); the
/// backend asserts they equal the template seed — the round-trip witness. Checkpoint.
const NR_BLK_READ_REPORT: u64 = 0xe2;
/// The block phase's terminal report — the backend asserts the matrix and finishes (boot's last act).
const NR_BLK_FINAL: u64 = 0xe3;

// ─── M5 Arc 5a: vGIC interrupt injection ────────────────────────────────────────────────────────────
//
// A synthetic guest enables the GICv3 CPU interface, signals the hypervisor to inject a virtual
// interrupt (via the list registers, see `crate::gic`), then acknowledges it through `ICC_IAR1_EL1` and
// reports the INTID. Proves the vGIC injection path end to end before any of it drives real Linux.

/// The domain running the vGIC test guest (a fresh `Hypervisor` for this phase).
const GIC_DOM: DomId = 1;
/// The guest's page-table root (the only frame it needs — it touches no guest data memory).
const F_GIC_ROOT: Mfn = 1;
/// The virtual INTID the hypervisor injects and the guest must acknowledge (an arbitrary SPI).
const GIC_TEST_INTID: u32 = 42;

/// The guest signals it has enabled its CPU interface and is ready for an injection (the hypervisor
/// injects [`GIC_TEST_INTID`] while servicing this HVC). A checkpoint.
const NR_GIC_READY: u64 = 0xd0;
/// The guest reports the INTID it acknowledged via `ICC_IAR1_EL1` (`x1`); the hypervisor asserts it
/// equals the injected INTID. A checkpoint.
const NR_GIC_REPORT: u64 = 0xd1;
/// The vGIC poll phase's terminal — chains into the async-delivery phase.
const NR_GIC_FINAL: u64 = 0xd2;
/// The async-delivery guest reports (from its EL1 IRQ vector) the INTID it took (`x1`). A checkpoint.
const NR_GIC_ASYNC_REPORT: u64 = 0xd3;
/// The async-delivery phase's terminal — chains into the virtual-timer phase.
const NR_GIC_ASYNC_FINAL: u64 = 0xd4;

// ─── M5 Arc 5b: the virtual timer ────────────────────────────────────────────────────────────────────
//
// A synthetic guest uses the ARM architected VIRTUAL timer (`CNTV`) for timekeeping: it reads the virtual
// count `CNTVCT_EL0`, programs a short deadline via `CNTV_TVAL_EL0`, enables the timer, and polls
// `CNTV_CTL_EL0.ISTATUS` until the compare condition fires — exactly the timer Linux reads constantly.

/// The guest reports the timer fired: `x1` = `CNTV_CTL_EL0` (with `ISTATUS`), `x2` = count before, `x3` =
/// count after. The hypervisor asserts the condition fired and the counter advanced. A checkpoint.
const NR_TIMER_REPORT: u64 = 0xc0;
/// The virtual-timer phase's terminal — chains into the PSCI phase.
const NR_TIMER_FINAL: u64 = 0xc1;

// ─── M5 Arc 5c: PSCI ─────────────────────────────────────────────────────────────────────────────────
//
// The Power State Coordination Interface — how a guest (and Linux) queries power management and powers
// down. The guest invokes PSCI via `HVC` (the DTB will say `method = "hvc"`); the hypervisor recognizes
// the PSCI function IDs and services them. A synthetic guest queries the version and powers off.

/// PSCI function IDs (SMC Calling Convention). `PSCI_VERSION`/`SYSTEM_OFF`/`PSCI_FEATURES` are the 32-bit
/// (SMC32) IDs; `CPU_ON`/`AFFINITY_INFO` are 64-bit (SMC64) and not needed for a single-CPU guest.
const PSCI_VERSION_FID: u64 = 0x8400_0000;
const PSCI_FEATURES_FID: u64 = 0x8400_000A;
const PSCI_SYSTEM_OFF_FID: u64 = 0x8400_0008;
/// The PSCI version the hypervisor reports: v1.1 (major 1 << 16 | minor 1).
const PSCI_VERSION_1_1: u64 = 0x0001_0001;
/// PSCI return code: the requested function is not implemented.
const PSCI_NOT_SUPPORTED: u64 = (-1i64) as u64;

/// The guest reports the PSCI version it read (`x1`); the hypervisor asserts it equals what it returned.
const NR_PSCI_REPORT: u64 = 0xb0;

// ─── M5 Arc 5d: the timer TICK — a physical interrupt delivered to the guest ──────────────────────────
//
// The keystone. A guest's virtual timer (`CNTV`) fires the physical PPI 27, routed to EL2 by
// `HCR_EL2.IMO`; the EL2 IRQ handler ([`handle_guest_irq`]) acknowledges it and injects the matching
// VIRTUAL interrupt, which the guest takes at its EL1 vector — a real, asynchronous, hardware-driven
// timer tick (the same receive→inject path virtio interrupts will reuse).

/// The guest reports (from its EL1 IRQ vector) the INTID of the timer tick it took (`x1`); the hypervisor
/// asserts it is the virtual-timer INTID. A checkpoint.
const NR_TIMER_IRQ_REPORT: u64 = 0xa0;
/// The timer-tick phase's terminal report (the boot's last act).
const NR_TIMER_IRQ_FINAL: u64 = 0xa1;

// ─── M5 Arc 6: the thesis — vault + disposable, non-interference ──────────────────────────────────────
//
// The finale, composing the proven arcs. A control domain (dom0) spawns a VAULT (holds an un-forgeable
// secret in its own distinct-VMID Stage-2, no channels out) and a DISPOSABLE (its own frames + a CoW
// overlay on the shared RO template). The disposable runs and PROBES the vault's secret → hardware
// translation fault (non-interference, Arc 2); then dom0 destroys the disposable clean (Arc 0), leaving
// the vault's secret untouched and the CoW template pristine (Arc 4). "The audit IS the arc" (Audit #3):
// enumerate every vault→disposable channel → none → bridge to the model's Tier-D non-interference.

/// The disposable domain (the running guest — a fresh `Hypervisor` for this phase).
const DISP_DOM: DomId = 1;
/// The vault domain (holds the secret; created + live, its secret seeded by the hypervisor).
const VAULT_DOM: DomId = 2;

// Frames (distinct global `Mfn`s). The disposable owns a root + a data frame; the vault owns a root + a
// secret frame. Distinct Mfn → distinct host PA → distinct per-VMID Stage-2 leaf (Arc 2).
const F_DISP_ROOT: Mfn = 1;
const F_DISP_DATA: Mfn = 2;
const F_VAULT_ROOT: Mfn = 3;
const F_VAULT_SECRET: Mfn = 4;

/// The disposable's own-frame sentinel (proves its authorized write works).
const SENTINEL_DISP: u64 = 0xD15D;
/// The vault's un-forgeable secret — a distinctive marker seeded HV-side into the vault's secret frame.
/// Its first 8 bytes (`V4ULTSEC`) are what the disposable's probe would read if isolation broke; a
/// `FORBIDDEN_MARKERS` guard on that token catches it on the console (it appears there only if the probe
/// read it). Must NEVER reach the disposable.
const VAULT_SECRET_MARKER: &[u8] = b"V4ULTSEC-forbidden-must-not-reach-the-disposable\n";

/// The disposable's CoW tenant (its disk = an overlay on the shared template).
const DISP_TENANT: usize = 0;
/// The shared template the disposable's disk is a CoW overlay on — seeded once; must stay pristine when
/// the disposable is destroyed (the Arc-4 property, re-cashed on the lifecycle).
const THESIS_TEMPLATE_MARKER: &[u8] = b"thesis-golden-template-pristine";
/// What the disposable's overlay is seeded with, so its disk has diverged from the template before it is
/// discarded on teardown.
const DISP_DISK_MARKER: &[u8] = b"disposable-overlay-scratch";

/// The frame offsets the disposable guest builds its IPAs from (`movz DATA_HI, lsl#16; movk OFF`).
const OFF_DISP_DATA: u64 = F_DISP_DATA as u64 * stage2::FRAME_SIZE;
const OFF_VAULT_SECRET: u64 = F_VAULT_SECRET as u64 * stage2::FRAME_SIZE;

/// The disposable reports (`x1`=own-frame readback, `x2`=the value its probe of the vault secret read —
/// stale iff the probe faulted). The hypervisor asserts its own write landed AND the probe did not read
/// the secret. A checkpoint.
const NR_THESIS_POS: u64 = 0x90;
/// The thesis phase's terminal — the hypervisor destroys the disposable and runs the non-interference +
/// lifecycle + channel-enumeration audit (the boot's last act).
const NR_THESIS_FINAL: u64 = 0x91;

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

// ---------------------------------------------------------------------------------------------
// The virtio-console driver guest program (M5 Arc 3). It reads the virtio-mmio identity registers
// (each `ldr w` traps to EL2 — the device window is unmapped in Stage-2 — and is trap-and-emulated),
// reports them, then finishes. Steps 2-4 extend this same program to drive the Status handshake, set
// up the granted virtqueue, write a buffer, and kick QueueNotify. Position-independent as the others.
// ---------------------------------------------------------------------------------------------
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .global __guest5_tpl_start
__guest5_tpl_start:
    // x10 = VIRTIO_MMIO_BASE (0x0a00_0000). Every access below faults (unmapped) → trap-and-emulate.
    movz    x10, #{VIRTIO_HI}, lsl #16
    // ── identity registers (32-bit `ldr w`) ──
    ldr     w1, [x10, #0x000]              // MagicValue  → expect "virt"
    ldr     w2, [x10, #0x004]              // Version     → expect 2
    ldr     w3, [x10, #0x008]              // DeviceID    → expect 3 (console)
    ldr     w4, [x10, #0x00c]              // VendorID
    mov     x0, #{NR_VIRTIO_ID}
    hvc     #0                             // backend asserts the four identity values

    // ── device negotiation handshake (virtio 1.x §3.1.1) ──
    str     wzr, [x10, #0x070]             // Status = 0 (reset)
    mov     w0, #3                         // ACKNOWLEDGE | DRIVER
    str     w0, [x10, #0x070]
    // read device features word 1 (bits 32..63) → expect VIRTIO_F_VERSION_1 (bit 0 of word 1)
    mov     w0, #1
    str     w0, [x10, #0x014]              // DeviceFeaturesSel = 1
    ldr     w5, [x10, #0x010]              // DeviceFeatures[word 1]
    // accept exactly those features: DriverFeatures[word 1] = what the device offered
    mov     w0, #1
    str     w0, [x10, #0x024]              // DriverFeaturesSel = 1
    str     w5, [x10, #0x020]              // DriverFeatures[word 1] = VERSION_1
    // FEATURES_OK, then read Status back — the device must leave FEATURES_OK set (features accepted)
    mov     w0, #0xb                       // ACKNOWLEDGE | DRIVER | FEATURES_OK (1|2|8)
    str     w0, [x10, #0x070]
    ldr     w6, [x10, #0x070]              // Status readback
    mov     x1, x5                         // report: device features word 1
    mov     x2, x6                         // report: status readback
    mov     x0, #{NR_VIRTIO_NEGOTIATED}
    hvc     #0                             // backend asserts VERSION_1 negotiated + FEATURES_OK sticky

    // ── queue 0 setup ── (x15 = F_VQ ipa: desc@+0, avail@+0x100, used@+0x200; x16 = F_BUF ipa)
    movz    x15, #{DATA_HI}, lsl #16
    movk    x15, #{VQ_OFF}
    movz    x16, #{DATA_HI}, lsl #16
    movk    x16, #{BUF_OFF}
    str     wzr, [x10, #0x030]             // QueueSel = 0
    mov     w0, #8
    str     w0, [x10, #0x038]              // QueueNum = 8
    mov     w0, w15
    str     w0, [x10, #0x080]              // QueueDescLow = F_VQ ipa
    str     wzr, [x10, #0x084]             // QueueDescHigh = 0
    add     w0, w15, #0x100
    str     w0, [x10, #0x090]              // QueueDriverLow = avail ring
    str     wzr, [x10, #0x094]
    add     w0, w15, #0x200
    str     w0, [x10, #0x0a0]              // QueueDeviceLow = used ring
    str     wzr, [x10, #0x0a4]
    mov     w0, #1
    str     w0, [x10, #0x044]              // QueueReady = 1
    mov     w0, #0xf                       // Status = ACK|DRIVER|FEATURES_OK|DRIVER_OK
    str     w0, [x10, #0x070]

    // ── copy the message into the granted TX buffer (byte loop until NUL) ──
    adr     x11, 2f                        // source: the message bytes (in the RO+X guest image)
    mov     x12, x16                       // dest: F_BUF ipa
1:  ldrb    w14, [x11], #1
    cbz     w14, 3f
    strb    w14, [x12], #1
    b       1b
2:  .asciz "baleen-guest: hello over a granted virtqueue\n"
    .balign 4
3:  sub     x17, x12, x16                  // desc.len = bytes copied

    // ── build descriptor 0: addr = F_BUF, len, flags = 0 (device-read), next = 0 ──
    str     x16, [x15, #0]                 // desc[0].addr
    str     w17, [x15, #8]                 // desc[0].len
    strh    wzr, [x15, #12]                // desc[0].flags = 0
    strh    wzr, [x15, #14]                // desc[0].next = 0

    // ── available ring: ring[0] = desc 0, idx = 1 ──
    strh    wzr, [x15, #0x104]             // avail.ring[0] = 0
    mov     w0, #1
    strh    w0, [x15, #0x102]              // avail.idx = 1

    // ── kick the device ──
    str     wzr, [x10, #0x050]             // QueueNotify = 0 → backend drains the granted ring

    // ── the negative: a second buffer in an UN-GRANTED frame → the backend must refuse ──
    movz    x18, #{DATA_HI}, lsl #16
    movk    x18, #{UNGRANTED_OFF}          // x18 = frame_ipa(F_BUF_UNGRANTED) — owned, NOT granted
    adr     x11, 5f                        // a secret the backend must NOT be able to read
    mov     x12, x18
4:  ldrb    w14, [x11], #1
    cbz     w14, 6f
    strb    w14, [x12], #1
    b       4b
5:  .asciz "SECRET-ungranted-must-not-appear\n"
    .balign 4
6:  sub     x17, x12, x18                  // len
    // descriptor 1: addr = F_BUF_UNGRANTED, len, flags = 0
    add     x19, x15, #16                  // &desc[1]
    str     x18, [x19, #0]
    str     w17, [x19, #8]
    strh    wzr, [x19, #12]
    strh    wzr, [x19, #14]
    // available ring: ring[1] = desc 1, idx = 2
    mov     w0, #1
    strh    w0, [x15, #0x106]              // avail.ring[1] = 1
    mov     w0, #2
    strh    w0, [x15, #0x102]              // avail.idx = 2
    str     wzr, [x10, #0x050]             // kick again → backend refuses the un-granted buffer

    // ── terminal ──
    mov     x0, #{NR_VIRTIO_FINAL}
    hvc     #0
0:  wfe
    b       0b
    .global __guest5_tpl_end
__guest5_tpl_end:
    "#,
    VIRTIO_HI = const VIRTIO_MMIO_HI,
    DATA_HI = const DATA_IPA_HI,
    VQ_OFF = const VQ_FRAME_OFF,
    BUF_OFF = const BUF_FRAME_OFF,
    UNGRANTED_OFF = const UNGRANTED_FRAME_OFF,
    NR_VIRTIO_ID = const NR_VIRTIO_ID,
    NR_VIRTIO_NEGOTIATED = const NR_VIRTIO_NEGOTIATED,
    NR_VIRTIO_FINAL = const NR_VIRTIO_FINAL,
);

// The virtio-blk READER driver guest program (M5 Arc 4). It identifies + negotiates the block device
// (identical handshake to the console — the shared virtio-mmio transport), sets up queue 0, then issues
// ONE read request: a descriptor CHAIN of { header (device-read) → data buffer (device-WRITE) → status
// (device-write) } for sector 0, kicks QueueNotify, and reports the first 8 bytes the backend DMA'd into
// its data buffer. Used by BOTH block tenant phases (phase 6 tenant 0's read de-risk; phase 7 tenant 1's
// isolation read). Position-independent as the others.
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .global __guest_blk_read_tpl_start
__guest_blk_read_tpl_start:
    // x10 = VIRTIO_MMIO_BASE (0x0a00_0000). Every access below faults (unmapped) → trap-and-emulate.
    movz    x10, #{VIRTIO_HI}, lsl #16
    // ── identity registers ──
    ldr     w1, [x10, #0x000]              // MagicValue → "virt"
    ldr     w2, [x10, #0x004]              // Version    → 2
    ldr     w3, [x10, #0x008]              // DeviceID   → 2 (block)
    ldr     w4, [x10, #0x00c]              // VendorID
    mov     x0, #{NR_BLK_ID}
    hvc     #0
    // ── negotiation handshake (virtio 1.x §3.1.1) — identical to the console ──
    str     wzr, [x10, #0x070]            // Status = 0 (reset)
    mov     w0, #3
    str     w0, [x10, #0x070]             // ACKNOWLEDGE | DRIVER
    mov     w0, #1
    str     w0, [x10, #0x014]             // DeviceFeaturesSel = 1
    ldr     w5, [x10, #0x010]             // DeviceFeatures[word 1]
    mov     w0, #1
    str     w0, [x10, #0x024]             // DriverFeaturesSel = 1
    str     w5, [x10, #0x020]             // DriverFeatures[word 1] = VERSION_1
    mov     w0, #0xb
    str     w0, [x10, #0x070]             // ACKNOWLEDGE | DRIVER | FEATURES_OK
    ldr     w6, [x10, #0x070]             // Status readback
    mov     x1, x5
    mov     x2, x6
    mov     x0, #{NR_BLK_NEGOTIATED}
    hvc     #0
    // ── queue 0 setup ── (x15 = F_BLK_VQ ipa; x13 = F_BLK_HDR ipa; x14 = F_BLK_IO ipa)
    movz    x15, #{DATA_HI}, lsl #16
    movk    x15, #{VQ_OFF}
    movz    x13, #{DATA_HI}, lsl #16
    movk    x13, #{HDR_OFF}
    movz    x14, #{DATA_HI}, lsl #16
    movk    x14, #{IO_OFF}
    str     wzr, [x10, #0x030]            // QueueSel = 0
    mov     w0, #8
    str     w0, [x10, #0x038]             // QueueNum = 8
    mov     w0, w15
    str     w0, [x10, #0x080]             // QueueDescLow = F_BLK_VQ
    str     wzr, [x10, #0x084]
    add     w0, w15, #0x100
    str     w0, [x10, #0x090]             // QueueDriverLow = avail ring
    str     wzr, [x10, #0x094]
    add     w0, w15, #0x200
    str     w0, [x10, #0x0a0]             // QueueDeviceLow = used ring
    str     wzr, [x10, #0x0a4]
    mov     w0, #1
    str     w0, [x10, #0x044]             // QueueReady = 1
    mov     w0, #0xf
    str     w0, [x10, #0x070]             // Status = ACK|DRIVER|FEATURES_OK|DRIVER_OK
    // ── build the request header @ F_BLK_HDR: type=T_IN(0), reserved=0, sector=0 = 16 zero bytes ──
    stp     xzr, xzr, [x13]
    // ── build the descriptor chain @ F_BLK_VQ (desc table @ +0) ──
    // desc[0]: header — addr=F_BLK_HDR, len=16, flags=NEXT(1), next=1
    str     x13, [x15, #0]
    mov     w0, #16
    str     w0, [x15, #8]
    mov     w0, #1
    strh    w0, [x15, #12]                // flags = NEXT
    mov     w0, #1
    strh    w0, [x15, #14]                // next = 1
    // desc[1]: data — addr=F_BLK_IO, len=512, flags=NEXT|WRITE(3), next=2  (device-writable)
    str     x14, [x15, #16]
    mov     w0, #512
    str     w0, [x15, #24]
    mov     w0, #3
    strh    w0, [x15, #28]                // flags = NEXT | WRITE
    mov     w0, #2
    strh    w0, [x15, #30]                // next = 2
    // desc[2]: status — addr=F_BLK_IO+0x200, len=1, flags=WRITE(2), next=0  (device-writable)
    add     x0, x14, #{STATUS_OFF}
    str     x0, [x15, #32]
    mov     w0, #1
    str     w0, [x15, #40]
    mov     w0, #2
    strh    w0, [x15, #44]                // flags = WRITE
    strh    wzr, [x15, #46]               // next = 0
    // ── available ring: ring[0] = desc 0, idx = 1 ──
    strh    wzr, [x15, #0x104]            // avail.ring[0] = 0
    mov     w0, #1
    strh    w0, [x15, #0x102]             // avail.idx = 1
    // ── kick the device → backend walks the chain, CoW-reads sector 0, DMAs it into F_BLK_IO ──
    str     wzr, [x10, #0x050]            // QueueNotify = 0
    // ── report the first 8 bytes the backend wrote into the data buffer ──
    ldr     x1, [x14, #0]
    mov     x0, #{NR_BLK_READ_REPORT}
    hvc     #0
    // ── terminal ──
    mov     x0, #{NR_BLK_FINAL}
    hvc     #0
0:  wfe
    b       0b
    .global __guest_blk_read_tpl_end
__guest_blk_read_tpl_end:
    "#,
    VIRTIO_HI = const VIRTIO_MMIO_HI,
    DATA_HI = const DATA_IPA_HI,
    VQ_OFF = const BLK_VQ_OFF,
    HDR_OFF = const BLK_HDR_OFF,
    IO_OFF = const BLK_IO_OFF,
    STATUS_OFF = const BLK_STATUS_OFF_IN_IO,
    NR_BLK_ID = const NR_BLK_ID,
    NR_BLK_NEGOTIATED = const NR_BLK_NEGOTIATED,
    NR_BLK_READ_REPORT = const NR_BLK_READ_REPORT,
    NR_BLK_FINAL = const NR_BLK_FINAL,
);

// The virtio-blk WRITER driver guest program (M5 Arc 4, tenant 0 / phase 6). It identifies + negotiates,
// sets up queue 0, then issues THREE requests over the shared descriptor chain:
//   (1) READ sector 0 — de-risks the read path and reports the template it round-tripped (positive);
//   (2) WRITE the poison payload to sector 0 — lands in tenant 0's CoW overlay, never the template;
//   (3) the NEGATIVE — a READ whose data buffer points at an UN-GRANTED frame → the backend refuses.
// desc0 (header) and desc2 (status) are built once; only desc1 (the data buffer) + the header contents
// change per request. Position-independent as the others.
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .global __guest_blk_write_tpl_start
__guest_blk_write_tpl_start:
    movz    x10, #{VIRTIO_HI}, lsl #16
    // ── identity ──
    ldr     w1, [x10, #0x000]
    ldr     w2, [x10, #0x004]
    ldr     w3, [x10, #0x008]
    ldr     w4, [x10, #0x00c]
    mov     x0, #{NR_BLK_ID}
    hvc     #0
    // ── negotiation (identical to the console/reader) ──
    str     wzr, [x10, #0x070]
    mov     w0, #3
    str     w0, [x10, #0x070]
    mov     w0, #1
    str     w0, [x10, #0x014]
    ldr     w5, [x10, #0x010]
    mov     w0, #1
    str     w0, [x10, #0x024]
    str     w5, [x10, #0x020]
    mov     w0, #0xb
    str     w0, [x10, #0x070]
    ldr     w6, [x10, #0x070]
    mov     x1, x5
    mov     x2, x6
    mov     x0, #{NR_BLK_NEGOTIATED}
    hvc     #0
    // ── queue 0 setup ──  x15=F_BLK_VQ, x13=F_BLK_HDR, x14=F_BLK_IO, x18=F_BLK_UNGRANTED
    movz    x15, #{DATA_HI}, lsl #16
    movk    x15, #{VQ_OFF}
    movz    x13, #{DATA_HI}, lsl #16
    movk    x13, #{HDR_OFF}
    movz    x14, #{DATA_HI}, lsl #16
    movk    x14, #{IO_OFF}
    movz    x18, #{DATA_HI}, lsl #16
    movk    x18, #{UNGRANTED_OFF}
    str     wzr, [x10, #0x030]
    mov     w0, #8
    str     w0, [x10, #0x038]
    mov     w0, w15
    str     w0, [x10, #0x080]
    str     wzr, [x10, #0x084]
    add     w0, w15, #0x100
    str     w0, [x10, #0x090]
    str     wzr, [x10, #0x094]
    add     w0, w15, #0x200
    str     w0, [x10, #0x0a0]
    str     wzr, [x10, #0x0a4]
    mov     w0, #1
    str     w0, [x10, #0x044]
    mov     w0, #0xf
    str     w0, [x10, #0x070]
    // ── desc[0] (header) and desc[2] (status) — same for every request, build once ──
    str     x13, [x15, #0]                // desc0.addr = header
    mov     w0, #16
    str     w0, [x15, #8]                 // desc0.len = 16
    mov     w0, #1
    strh    w0, [x15, #12]                // desc0.flags = NEXT
    mov     w0, #1
    strh    w0, [x15, #14]                // desc0.next = 1
    add     x0, x14, #{STATUS_OFF}
    str     x0, [x15, #32]                // desc2.addr = status
    mov     w0, #1
    str     w0, [x15, #40]                // desc2.len = 1
    mov     w0, #2
    strh    w0, [x15, #44]                // desc2.flags = WRITE
    strh    wzr, [x15, #46]               // desc2.next = 0

    // ── Request 1: READ sector 0 (template) ──
    stp     xzr, xzr, [x13]               // header: type=T_IN(0), reserved=0, sector=0
    str     x14, [x15, #16]               // desc1.addr = F_BLK_IO (data)
    mov     w0, #512
    str     w0, [x15, #24]                // desc1.len = 512
    mov     w0, #3
    strh    w0, [x15, #28]                // desc1.flags = NEXT | WRITE (device-writable)
    mov     w0, #2
    strh    w0, [x15, #30]                // desc1.next = 2
    strh    wzr, [x15, #0x104]            // avail.ring[0] = 0
    mov     w0, #1
    strh    w0, [x15, #0x102]             // avail.idx = 1
    str     wzr, [x10, #0x050]            // kick → backend CoW-reads sector 0 into F_BLK_IO
    ldr     x1, [x14, #0]
    mov     x0, #{NR_BLK_READ_REPORT}
    hvc     #0                            // report the template bytes round-tripped

    // ── Request 2: WRITE the poison payload to sector 0 (→ tenant 0's overlay) ──
    adr     x11, 7f                       // copy the poison into F_BLK_IO's data area
    mov     x12, x14
1:  ldrb    w0, [x11], #1
    cbz     w0, 8f
    strb    w0, [x12], #1
    b       1b
7:  .asciz "POISON-blk-guest0-write-must-not-cross\n"
    .balign 4
8:  mov     w0, #1
    str     w0, [x13, #0]                 // header: type = T_OUT(1)
    str     wzr, [x13, #4]                // reserved = 0
    str     xzr, [x13, #8]                // sector = 0
    str     x14, [x15, #16]               // desc1.addr = F_BLK_IO (data)
    mov     w0, #512
    str     w0, [x15, #24]
    mov     w0, #1
    strh    w0, [x15, #28]                // desc1.flags = NEXT (device-READABLE, no WRITE)
    mov     w0, #2
    strh    w0, [x15, #30]                // desc1.next = 2
    strh    wzr, [x15, #0x106]            // avail.ring[1] = 0
    mov     w0, #2
    strh    w0, [x15, #0x102]             // avail.idx = 2
    str     wzr, [x10, #0x050]            // kick → backend CoW-writes tenant 0's overlay

    // ── Request 3: the NEGATIVE — READ into an UN-GRANTED buffer (backend must refuse) ──
    str     xzr, [x13, #0]                // header: type = T_IN(0), reserved=0
    str     xzr, [x13, #8]                // sector = 0
    str     x18, [x15, #16]               // desc1.addr = F_BLK_UNGRANTED (owned, NOT granted)
    mov     w0, #512
    str     w0, [x15, #24]
    mov     w0, #3
    strh    w0, [x15, #28]                // desc1.flags = NEXT | WRITE
    mov     w0, #2
    strh    w0, [x15, #30]                // desc1.next = 2
    strh    wzr, [x15, #0x108]            // avail.ring[2] = 0
    mov     w0, #3
    strh    w0, [x15, #0x102]             // avail.idx = 3
    str     wzr, [x10, #0x050]            // kick → backend refuses the un-granted data buffer

    // ── terminal ──
    mov     x0, #{NR_BLK_FINAL}
    hvc     #0
0:  wfe
    b       0b
    .global __guest_blk_write_tpl_end
__guest_blk_write_tpl_end:
    "#,
    VIRTIO_HI = const VIRTIO_MMIO_HI,
    DATA_HI = const DATA_IPA_HI,
    VQ_OFF = const BLK_VQ_OFF,
    HDR_OFF = const BLK_HDR_OFF,
    IO_OFF = const BLK_IO_OFF,
    UNGRANTED_OFF = const BLK_UNGRANTED_OFF,
    STATUS_OFF = const BLK_STATUS_OFF_IN_IO,
    NR_BLK_ID = const NR_BLK_ID,
    NR_BLK_NEGOTIATED = const NR_BLK_NEGOTIATED,
    NR_BLK_READ_REPORT = const NR_BLK_READ_REPORT,
    NR_BLK_FINAL = const NR_BLK_FINAL,
);

// The vGIC test guest program (M5 Arc 5a). It enables the GICv3 CPU interface (system-register access,
// priority mask, Group 1), signals the hypervisor to inject a virtual interrupt, then ACKNOWLEDGES the
// pending interrupt via `ICC_IAR1_EL1` and reports the INTID. This first step POLLS the acknowledge
// register with interrupts still masked (proving the injection reaches the CPU interface); async
// vectored delivery is the next step. Straight-line / stack-free, position-independent as the others.
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .global __guest_gic_poll_tpl_start
__guest_gic_poll_tpl_start:
    // ── enable the GICv3 CPU system-register interface at EL1 ──
    mrs     x0, ICC_SRE_EL1
    orr     x0, x0, #1                     // SRE = 1 (use the system-register interface)
    msr     ICC_SRE_EL1, x0
    isb
    mov     x0, #0xff
    msr     ICC_PMR_EL1, x0                // priority mask = allow every priority
    mov     x0, #1
    msr     ICC_IGRPEN1_EL1, x0            // enable Group 1 interrupts
    isb
    // ── ready: the hypervisor injects GIC_TEST_INTID while servicing this HVC ──
    mov     x0, #{NR_GIC_READY}
    hvc     #0
    // ── acknowledge the injected virtual interrupt and report its INTID ──
    mrs     x1, ICC_IAR1_EL1               // → the pending INTID (1023 if none/spurious)
    msr     ICC_EOIR1_EL1, x1              // end of interrupt (priority drop + deactivate)
    mov     x0, #{NR_GIC_REPORT}
    hvc     #0                             // report x1 = the acknowledged INTID
    // ── terminal ──
    mov     x0, #{NR_GIC_FINAL}
    hvc     #0
0:  wfe
    b       0b
    .global __guest_gic_poll_tpl_end
__guest_gic_poll_tpl_end:
    "#,
    NR_GIC_READY = const NR_GIC_READY,
    NR_GIC_REPORT = const NR_GIC_REPORT,
    NR_GIC_FINAL = const NR_GIC_FINAL,
);

// The vGIC ASYNC-delivery test guest program (M5 Arc 5b). Unlike the poll guest, it installs its OWN
// EL1 exception vector table (`VBAR_EL1`), unmasks IRQs (`DAIFClr`), and *takes* the injected virtual
// interrupt at its IRQ vector — real vectored delivery, the mechanism Linux depends on. The whole blob
// is `0x800`-aligned (so the vector table's runtime address, `0x800`-aligned relative to the blob start,
// is `0x800`-aligned as `VBAR_EL1` requires — the blob is copied to the 2 MiB-aligned guest RAM base).
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 0x800
    .global __guest_gic_async_tpl_start
__guest_gic_async_tpl_start:
    // ── point VBAR_EL1 at our vector table (0x800-aligned, below) ──
    adr     x0, 9f
    msr     VBAR_EL1, x0
    isb
    // ── enable the GICv3 CPU interface (as the poll guest) ──
    mrs     x0, ICC_SRE_EL1
    orr     x0, x0, #1
    msr     ICC_SRE_EL1, x0
    isb
    mov     x0, #0xff
    msr     ICC_PMR_EL1, x0
    mov     x0, #1
    msr     ICC_IGRPEN1_EL1, x0
    isb
    // ── ready: the hypervisor injects the virtual interrupt while servicing this HVC ──
    mov     x0, #{NR_GIC_READY}
    hvc     #0
    // ── unmask IRQ: the pending virtual interrupt is now taken at the IRQ vector below ──
    msr     DAIFClr, #2
    isb
1:  wfi
    b       1b

    // ── EL1 exception vector table (16 entries, 0x80 apart). The guest runs at EL1h (SP_ELx), so an
    //    IRQ vectors to offset 0x280 (Current EL with SP_ELx, IRQ). Others spin (never expected). ──
    .balign 0x800
9:
    b       8f                            // 0x000 Current EL SP0, Synchronous
    .balign 0x80
    b       8f                            // 0x080 Current EL SP0, IRQ
    .balign 0x80
    b       8f                            // 0x100 Current EL SP0, FIQ
    .balign 0x80
    b       8f                            // 0x180 Current EL SP0, SError
    .balign 0x80
    b       8f                            // 0x200 Current EL SPx, Synchronous
    .balign 0x80
    // 0x280 Current EL SPx, IRQ — the injected virtual interrupt lands here
    mrs     x1, ICC_IAR1_EL1              // acknowledge → INTID
    msr     ICC_EOIR1_EL1, x1             // end of interrupt
    mov     x0, #{NR_GIC_ASYNC_REPORT}
    hvc     #0                            // report x1 = the async-delivered INTID
    mov     x0, #{NR_GIC_ASYNC_FINAL}
    hvc     #0
7:  wfe
    b       7b
    .balign 0x80
8:  wfe                                    // catch-all for any unexpected vector
    b       8b
    .global __guest_gic_async_tpl_end
__guest_gic_async_tpl_end:
    "#,
    NR_GIC_READY = const NR_GIC_READY,
    NR_GIC_ASYNC_REPORT = const NR_GIC_ASYNC_REPORT,
    NR_GIC_ASYNC_FINAL = const NR_GIC_ASYNC_FINAL,
);

// The virtual-timer test guest program (M5 Arc 5b). It uses the ARM architected VIRTUAL timer for
// timekeeping: read the count, program a short deadline (CNTV_TVAL), enable the timer, and poll
// CNTV_CTL.ISTATUS until the compare condition fires — no interrupts (the timer *interrupt* rides the
// shared EL2-physical-IRQ delivery path, a later step). Straight-line / stack-free, position-independent.
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .global __guest_timer_tpl_start
__guest_timer_tpl_start:
    mrs     x2, CNTVCT_EL0                 // virtual count BEFORE
    mov     x0, #0x8000
    msr     CNTV_TVAL_EL0, x0              // fire after ~0x8000 ticks (a short, deterministic deadline)
    mov     x0, #1
    msr     CNTV_CTL_EL0, x0               // ENABLE = 1, IMASK = 0
    isb
1:  mrs     x0, CNTV_CTL_EL0
    tbz     x0, #2, 1b                     // spin until ISTATUS (bit 2) — the compare condition fired
    mrs     x3, CNTVCT_EL0                 // virtual count AFTER
    msr     CNTV_CTL_EL0, xzr              // disable the timer
    mov     x1, x0                         // report: CNTV_CTL (with ISTATUS set)
    mov     x0, #{NR_TIMER_REPORT}
    hvc     #0                             // x1=ctl, x2=before, x3=after
    mov     x0, #{NR_TIMER_FINAL}
    hvc     #0
0:  wfe
    b       0b
    .global __guest_timer_tpl_end
__guest_timer_tpl_end:
    "#,
    NR_TIMER_REPORT = const NR_TIMER_REPORT,
    NR_TIMER_FINAL = const NR_TIMER_FINAL,
);

// The PSCI test guest program (M5 Arc 5c). It queries the PSCI version via HVC, reports it, then powers
// off via PSCI SYSTEM_OFF (which the hypervisor treats as the guest's terminal — SYSTEM_OFF never
// returns). This is exactly how Linux uses PSCI (version probe at boot, SYSTEM_OFF at shutdown), with
// `method = "hvc"`. Straight-line / stack-free, position-independent.
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .global __guest_psci_tpl_start
__guest_psci_tpl_start:
    // PSCI_VERSION (0x84000000) via HVC → version in x0
    movz    x0, #0x8400, lsl #16
    hvc     #0
    mov     x1, x0                         // report the version the hypervisor returned
    mov     x0, #{NR_PSCI_REPORT}
    hvc     #0
    // SYSTEM_OFF (0x84000008) — the guest powers off; the hypervisor does not return
    movz    x0, #0x8400, lsl #16
    movk    x0, #0x0008
    hvc     #0
0:  wfe
    b       0b
    .global __guest_psci_tpl_end
__guest_psci_tpl_end:
    "#,
    NR_PSCI_REPORT = const NR_PSCI_REPORT,
);

// The timer-TICK test guest program (M5 Arc 5d). It installs its EL1 vector table, enables its virtual
// CPU interface, programs the virtual timer (CNTV) with IMASK=0, unmasks IRQs, and waits (`wfi`). When
// the timer fires, the physical PPI goes to EL2, which injects the virtual timer interrupt; the guest
// TAKES it at its IRQ vector — a real hardware-driven tick. 0x800-aligned blob (for VBAR_EL1, as the
// async guest). Position-independent.
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 0x800
    .global __guest_timer_irq_tpl_start
__guest_timer_irq_tpl_start:
    adr     x0, 9f
    msr     VBAR_EL1, x0
    isb
    mrs     x0, ICC_SRE_EL1
    orr     x0, x0, #1
    msr     ICC_SRE_EL1, x0
    isb
    mov     x0, #0xff
    msr     ICC_PMR_EL1, x0
    mov     x0, #1
    msr     ICC_IGRPEN1_EL1, x0
    isb
    // program the virtual timer: fire after ~0x8000 ticks, ENABLE=1, IMASK=0 (interrupt not masked)
    mov     x0, #0x8000
    msr     CNTV_TVAL_EL0, x0
    mov     x0, #1
    msr     CNTV_CTL_EL0, x0
    isb
    // unmask IRQ and wait — the tick arrives asynchronously at the vector below
    msr     DAIFClr, #2
    isb
1:  wfi
    b       1b

    .balign 0x800
9:
    b       8f                            // 0x000 Current EL SP0, Synchronous
    .balign 0x80
    b       8f                            // 0x080 Current EL SP0, IRQ
    .balign 0x80
    b       8f                            // 0x100 Current EL SP0, FIQ
    .balign 0x80
    b       8f                            // 0x180 Current EL SP0, SError
    .balign 0x80
    b       8f                            // 0x200 Current EL SPx, Synchronous
    .balign 0x80
    // 0x280 Current EL SPx, IRQ — the virtual timer tick lands here
    mrs     x1, ICC_IAR1_EL1              // acknowledge → INTID (27, the virtual timer)
    msr     ICC_EOIR1_EL1, x1
    mov     x0, #{NR_TIMER_IRQ_REPORT}
    hvc     #0
    mov     x0, #{NR_TIMER_IRQ_FINAL}
    hvc     #0
7:  wfe
    b       7b
    .balign 0x80
8:  wfe
    b       8b
    .global __guest_timer_irq_tpl_end
__guest_timer_irq_tpl_end:
    "#,
    NR_TIMER_IRQ_REPORT = const NR_TIMER_IRQ_REPORT,
    NR_TIMER_IRQ_FINAL = const NR_TIMER_IRQ_FINAL,
);

// The DISPOSABLE guest program (M5 Arc 6). It writes its own data frame (authorized — succeeds), reads it
// back, then PROBES the vault's secret frame — an IPA its Stage-2 does not map (the secret lives in the
// vault's distinct-VMID Stage-2) — which faults to EL2 (translation); the handler records it and resumes
// past. It reports its own read-back (x1) and the value the probe read (x2, stale iff it faulted — the
// disposable NEVER obtains the secret). Straight-line / stack-free, position-independent.
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .global __guest_disposable_tpl_start
__guest_disposable_tpl_start:
    // ── authorized: write my own data frame, read it back ──
    movz    x2, #{DATA_HI}, lsl #16
    movk    x2, #{OFF_MINE}
    movz    x3, #{SENTINEL_DISP}
    str     x3, [x2]
    ldr     x1, [x2]                        // x1 = my read-back (expect SENTINEL_DISP)
    // ── non-interference: probe the vault's secret → translation fault (recorded, resumed past) ──
    movz    x2, #{DATA_HI}, lsl #16
    movk    x2, #{OFF_SECRET}
    mov     x4, #0
    ldr     x4, [x2]                        // faults; on resume x4 is UNCHANGED (0) — never the secret
    mov     x2, x4                          // x2 = the value the probe read (0 iff it faulted)
    mov     x0, #{NR_THESIS_POS}
    hvc     #0                              // report x1 = own read-back, x2 = probe value
    mov     x0, #{NR_THESIS_FINAL}
    hvc     #0
0:  wfe
    b       0b
    .global __guest_disposable_tpl_end
__guest_disposable_tpl_end:
    "#,
    DATA_HI = const DATA_IPA_HI,
    OFF_MINE = const OFF_DISP_DATA,
    OFF_SECRET = const OFF_VAULT_SECRET,
    SENTINEL_DISP = const SENTINEL_DISP,
    NR_THESIS_POS = const NR_THESIS_POS,
    NR_THESIS_FINAL = const NR_THESIS_FINAL,
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

/// The virtio-mmio console device state (M5 Arc 3) — the trap-and-emulate register file.
struct VirtioCell(UnsafeCell<crate::virtio::VirtioConsole>);
// SAFETY: single boot CPU; touched only by the straight-line, non-nested guest trap handler (the MMIO
// emulation) and the phase-5 setup before that guest runs. No concurrent access. Same discipline as
// `GUEST_HV`.
unsafe impl Sync for VirtioCell {}
static VIRTIO_DEV: VirtioCell = VirtioCell(UnsafeCell::new(crate::virtio::VirtioConsole::new()));

/// Borrow the virtio-mmio console device state (M5 Arc 3).
fn virtio_dev() -> &'static mut crate::virtio::VirtioConsole {
    // SAFETY: single-CPU, non-nested handler; exclusive access.
    unsafe { &mut *VIRTIO_DEV.0.get() }
}

/// The virtio-blk device state (M5 Arc 4) — a second trap-and-emulate register file, active only during
/// the block phases. Same single-CPU discipline as [`VIRTIO_DEV`].
struct BlkCell(UnsafeCell<crate::blk::VirtioBlk>);
// SAFETY: single boot CPU; touched only by the straight-line, non-nested guest trap handler and the
// block-phase setup before that guest runs. No concurrent access.
unsafe impl Sync for BlkCell {}
static BLK_DEV: BlkCell = BlkCell(UnsafeCell::new(crate::blk::VirtioBlk::new()));

/// Borrow the virtio-blk device register state (M5 Arc 4).
fn blk_dev() -> &'static mut crate::blk::VirtioBlk {
    // SAFETY: single-CPU, non-nested handler; exclusive access.
    unsafe { &mut *BLK_DEV.0.get() }
}

/// The copy-on-write disk (M5 Arc 4) — the shared read-only template + per-tenant overlays. **Persists
/// across the two block-phase `Hypervisor` rebuilds** (it is backend/device-model storage, not part of
/// the model), which is exactly what lets tenant 1 read the template tenant 0 left pristine. Seeded once
/// before the first block phase; never mapped into any guest's Stage-2 (unreachable by construction).
struct BlkDiskCell(UnsafeCell<crate::blk::BlkDisk>);
// SAFETY: single boot CPU; touched only by the non-nested backend (via the trap handler) and the
// one-time seed before the first block guest runs. No concurrent access.
unsafe impl Sync for BlkDiskCell {}
static BLK_DISK: BlkDiskCell = BlkDiskCell(UnsafeCell::new(crate::blk::BlkDisk::new()));

/// Borrow the copy-on-write disk (M5 Arc 4).
fn blk_disk() -> &'static mut crate::blk::BlkDisk {
    // SAFETY: single-CPU, non-nested handler; exclusive access.
    unsafe { &mut *BLK_DISK.0.get() }
}

/// Which virtio device the mmio window ([`crate::virtio::VIRTIO_MMIO_BASE`]) currently emulates — set at
/// each device phase's entry so [`handle_mmio`] routes a trapped register access to the right device.
/// The console (Arc 3) and block (Arc 4) phases run sequentially; only one device is live at a time.
#[derive(Clone, Copy, PartialEq)]
enum ActiveVirtio {
    None = 0,
    Console = 1,
    Blk = 2,
}
static ACTIVE_VIRTIO: AtomicU8 = AtomicU8::new(ActiveVirtio::None as u8);

fn set_active_virtio(which: ActiveVirtio) {
    ACTIVE_VIRTIO.store(which as u8, Ordering::Relaxed);
}
fn active_virtio() -> ActiveVirtio {
    match ACTIVE_VIRTIO.load(Ordering::Relaxed) {
        1 => ActiveVirtio::Console,
        2 => ActiveVirtio::Blk,
        _ => ActiveVirtio::None,
    }
}

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

/// M5 Arc 3: whether the driver read the four virtio-mmio identity registers correctly (magic /
/// version / device-id / vendor).
static VIRTIO_ID_OK: AtomicBool = AtomicBool::new(false);
/// M5 Arc 3: whether the driver negotiated `VIRTIO_F_VERSION_1` and the device left FEATURES_OK set.
static VIRTIO_NEGOTIATED_OK: AtomicBool = AtomicBool::new(false);
/// M5 Arc 3: whether the backend drained a buffer from the granted ring to the console (the positive).
static VIRTIO_DRAINED_OK: AtomicBool = AtomicBool::new(false);
/// M5 Arc 3: whether the backend REFUSED an un-granted access (the negative / diamond — step 4).
static VIRTIO_UNGRANTED_REFUSED: AtomicBool = AtomicBool::new(false);

/// M5 Arc 4: which tenant (per-guest CoW overlay) the current block phase runs — the backend keys its
/// disk accesses on this. Set at each block phase's entry.
static BLK_TENANT: AtomicU64 = AtomicU64::new(0);
/// M5 Arc 4: the driver read the four virtio-blk identity registers correctly (magic/version/id=2/vendor).
static BLK_ID_OK: AtomicBool = AtomicBool::new(false);
/// M5 Arc 4: the driver negotiated `VIRTIO_F_VERSION_1` and the device left FEATURES_OK set.
static BLK_NEGOTIATED_OK: AtomicBool = AtomicBool::new(false);
/// M5 Arc 4: whether a T_IN read the backend served for tenant `t` fell through to the TEMPLATE (a clean
/// sector) AND the round-trip bytes the guest reported matched the template seed — per tenant. Tenant 0's
/// bit witnesses "a clean sector reads the template"; tenant 1's witnesses **overlay-isolation** (it read
/// the template pristine, not tenant 0's poison).
static BLK_READ_TEMPLATE_OK: [AtomicBool; crate::blk::N_TENANTS] =
    [const { AtomicBool::new(false) }; crate::blk::N_TENANTS];
/// M5 Arc 4: a WRITE landed in the tenant's overlay and left the template pristine (template-immutability,
/// checked HV-side after tenant 0's write). Set in a later step.
static BLK_WRITE_ISOLATED_OK: AtomicBool = AtomicBool::new(false);
/// M5 Arc 4: the backend REFUSED an un-granted descriptor in the chain (the grant regression negative).
static BLK_UNGRANTED_REFUSED: AtomicBool = AtomicBool::new(false);

/// M5 Arc 5a: the guest acknowledged the injected virtual interrupt with the correct INTID (the vGIC
/// injection path reached the guest's CPU interface).
static GIC_INJECT_OK: AtomicBool = AtomicBool::new(false);
/// M5 Arc 5b: the guest took the injected virtual interrupt ASYNCHRONOUSLY at its EL1 IRQ vector (not by
/// polling) with the correct INTID — real vectored interrupt delivery, the mechanism Linux depends on.
static GIC_ASYNC_OK: AtomicBool = AtomicBool::new(false);
/// M5 Arc 5b: the guest used the virtual timer — programmed a deadline, the `CNTVCT` counter advanced,
/// and the `ISTATUS` compare condition fired (timekeeping, what Linux depends on).
static TIMER_OK: AtomicBool = AtomicBool::new(false);
/// M5 Arc 5c: the guest read the PSCI version the hypervisor reported (PSCI is discoverable).
static PSCI_VERSION_OK: AtomicBool = AtomicBool::new(false);
/// M5 Arc 5c: the guest powered off via PSCI `SYSTEM_OFF` (the hypervisor serviced it).
static PSCI_OFF_OK: AtomicBool = AtomicBool::new(false);
/// M5 Arc 5d: the EL2 IRQ handler fielded the physical virtual-timer interrupt (the tick reached EL2).
static TIMER_IRQ_FIRED: AtomicBool = AtomicBool::new(false);
/// M5 Arc 5d: the guest TOOK the timer tick at its EL1 IRQ vector with the virtual-timer INTID (the full
/// physical-IRQ → EL2 → inject → guest-vIRQ path — a real hardware-driven timer tick).
static TIMER_IRQ_OK: AtomicBool = AtomicBool::new(false);

/// M5 Arc 6: the disposable's authorized write landed AND its probe of the vault secret did NOT read it
/// (`x1`==sentinel, `x2`!=secret) — the disposable never obtained the secret.
static THESIS_POS_OK: AtomicBool = AtomicBool::new(false);

extern "C" {
    static __guest_tpl_start: u8;
    static __guest_tpl_end: u8;
    static __guest2_tpl_start: u8;
    static __guest2_tpl_end: u8;
    static __guest3_tpl_start: u8;
    static __guest3_tpl_end: u8;
    static __guest4_tpl_start: u8;
    static __guest4_tpl_end: u8;
    static __guest5_tpl_start: u8;
    static __guest5_tpl_end: u8;
    static __guest_blk_read_tpl_start: u8;
    static __guest_blk_read_tpl_end: u8;
    static __guest_blk_write_tpl_start: u8;
    static __guest_blk_write_tpl_end: u8;
    static __guest_gic_poll_tpl_start: u8;
    static __guest_gic_poll_tpl_end: u8;
    static __guest_gic_async_tpl_start: u8;
    static __guest_gic_async_tpl_end: u8;
    static __guest_timer_tpl_start: u8;
    static __guest_timer_tpl_end: u8;
    static __guest_psci_tpl_start: u8;
    static __guest_psci_tpl_end: u8;
    static __guest_timer_irq_tpl_start: u8;
    static __guest_timer_irq_tpl_end: u8;
    static __guest_disposable_tpl_start: u8;
    static __guest_disposable_tpl_end: u8;
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

// The vector trampoline for a lower-EL/AArch64 IRQ (slot 9) — a physical interrupt taken while the guest
// runs (M5 Arc 5d, the timer tick routed to EL2 by `HCR_EL2.IMO`). Same save/restore discipline as the
// sync trampoline: save x0..x30 so the guest is resumed byte-identical, field the interrupt in the Rust
// handler, restore, and `eret` — after which the pending *virtual* interrupt the handler injected is
// taken by the guest at its own EL1 vector.
global_asm!(
    r#"
    .section .text
    .balign 0x40
    .global __guest_irq_entry
__guest_irq_entry:
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
    bl      handle_guest_irq
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

/// **M5 Arc 5d — the EL2 IRQ handler.** A physical interrupt was taken to EL2 while the guest ran.
/// Acknowledge it; if it is the virtual-timer PPI, disable the (level-triggered) timer so it does not
/// immediately re-fire, then inject the matching *virtual* interrupt into the guest (delivered at the
/// guest's EL1 vector after the trampoline `eret`s). End the physical interrupt either way.
///
/// # Safety
/// `_frame` is the valid `&mut GuestFrame` the trampoline saved on the exception stack (unused here — the
/// handler touches only GIC/timer system state — but kept in the ABI so the trampoline is uniform).
#[no_mangle]
extern "C" fn handle_guest_irq(_frame: *mut GuestFrame) {
    let intid = gic::ack_physical();
    if intid == gic::VTIMER_INTID {
        gic::disable_vtimer(); // one-shot: stop the level-triggered PPI re-asserting after EOI
        TIMER_IRQ_FIRED.store(true, Ordering::Relaxed);
        gic::inject(gic::VTIMER_INTID); // hand the guest its own virtual timer interrupt
    }
    // INTID 1023 (spurious) or anything else: just complete it.
    if intid < 1020 {
        gic::eoi_physical(intid);
    }
}

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

/// Copy the **phase-5** (virtio-console driver) guest template into guest RAM and return its `entry`
/// guest-physical address (M5 Arc 3).
fn load_guest5() -> u64 {
    let tpl_start = core::ptr::addr_of!(__guest5_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest5_tpl_end) as usize;
    let ram_start = core::ptr::addr_of!(__guest_ram_start) as usize;
    let len = tpl_end - tpl_start;
    // SAFETY: as `load_guest` — in-image template source, reserved guest-RAM destination far larger
    // than the template, non-overlapping.
    unsafe {
        core::ptr::copy_nonoverlapping(tpl_start as *const u8, ram_start as *mut u8, len);
    }
    ram_start as u64
}

/// Copy the **virtio-blk reader** guest template into guest RAM and return its `entry` guest-physical
/// address (M5 Arc 4). Used by phase 7 (tenant 1's isolation read).
fn load_guest_blk_read() -> u64 {
    let tpl_start = core::ptr::addr_of!(__guest_blk_read_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest_blk_read_tpl_end) as usize;
    let ram_start = core::ptr::addr_of!(__guest_ram_start) as usize;
    let len = tpl_end - tpl_start;
    // SAFETY: as `load_guest` — in-image template source, reserved guest-RAM destination far larger
    // than the template, non-overlapping.
    unsafe {
        core::ptr::copy_nonoverlapping(tpl_start as *const u8, ram_start as *mut u8, len);
    }
    ram_start as u64
}

/// Copy the **virtio-blk writer** guest template into guest RAM and return its `entry` guest-physical
/// address (M5 Arc 4). Used by phase 6 (tenant 0: read, write-poison, and the un-granted negative).
fn load_guest_blk_write() -> u64 {
    let tpl_start = core::ptr::addr_of!(__guest_blk_write_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest_blk_write_tpl_end) as usize;
    let ram_start = core::ptr::addr_of!(__guest_ram_start) as usize;
    let len = tpl_end - tpl_start;
    // SAFETY: as `load_guest` — in-image template source, reserved guest-RAM destination far larger
    // than the template, non-overlapping.
    unsafe {
        core::ptr::copy_nonoverlapping(tpl_start as *const u8, ram_start as *mut u8, len);
    }
    ram_start as u64
}

/// Copy the **vGIC poll** guest template into guest RAM and return its `entry` guest-physical address
/// (M5 Arc 5a).
fn load_guest_gic_poll() -> u64 {
    let tpl_start = core::ptr::addr_of!(__guest_gic_poll_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest_gic_poll_tpl_end) as usize;
    let ram_start = core::ptr::addr_of!(__guest_ram_start) as usize;
    let len = tpl_end - tpl_start;
    // SAFETY: as `load_guest` — in-image template source, reserved guest-RAM destination far larger
    // than the template, non-overlapping.
    unsafe {
        core::ptr::copy_nonoverlapping(tpl_start as *const u8, ram_start as *mut u8, len);
    }
    ram_start as u64
}

/// Copy the **vGIC async-delivery** guest template into guest RAM and return its `entry` guest-physical
/// address (M5 Arc 5b). The template is `0x800`-aligned and the guest RAM base is 2 MiB-aligned, so the
/// vector table (`0x800`-aligned within the blob) lands at a `0x800`-aligned runtime address for `VBAR_EL1`.
fn load_guest_gic_async() -> u64 {
    let tpl_start = core::ptr::addr_of!(__guest_gic_async_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest_gic_async_tpl_end) as usize;
    let ram_start = core::ptr::addr_of!(__guest_ram_start) as usize;
    let len = tpl_end - tpl_start;
    // SAFETY: as `load_guest` — in-image template source, reserved guest-RAM destination far larger
    // than the template, non-overlapping. `ram_start` is 2 MiB-aligned so the blob's internal 0x800
    // alignment is preserved at runtime.
    unsafe {
        core::ptr::copy_nonoverlapping(tpl_start as *const u8, ram_start as *mut u8, len);
    }
    ram_start as u64
}

/// Copy the **virtual-timer** guest template into guest RAM and return its `entry` guest-physical address
/// (M5 Arc 5b).
fn load_guest_timer() -> u64 {
    let tpl_start = core::ptr::addr_of!(__guest_timer_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest_timer_tpl_end) as usize;
    let ram_start = core::ptr::addr_of!(__guest_ram_start) as usize;
    let len = tpl_end - tpl_start;
    // SAFETY: as `load_guest` — in-image template source, reserved guest-RAM destination far larger
    // than the template, non-overlapping.
    unsafe {
        core::ptr::copy_nonoverlapping(tpl_start as *const u8, ram_start as *mut u8, len);
    }
    ram_start as u64
}

/// Copy the **PSCI** guest template into guest RAM and return its `entry` guest-physical address
/// (M5 Arc 5c).
fn load_guest_psci() -> u64 {
    let tpl_start = core::ptr::addr_of!(__guest_psci_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest_psci_tpl_end) as usize;
    let ram_start = core::ptr::addr_of!(__guest_ram_start) as usize;
    let len = tpl_end - tpl_start;
    // SAFETY: as `load_guest` — in-image template source, reserved guest-RAM destination far larger
    // than the template, non-overlapping.
    unsafe {
        core::ptr::copy_nonoverlapping(tpl_start as *const u8, ram_start as *mut u8, len);
    }
    ram_start as u64
}

/// Copy the **timer-tick** guest template into guest RAM and return its `entry` guest-physical address
/// (M5 Arc 5d). 0x800-aligned blob → 0x800-aligned vector table at runtime (for `VBAR_EL1`).
fn load_guest_timer_irq() -> u64 {
    let tpl_start = core::ptr::addr_of!(__guest_timer_irq_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest_timer_irq_tpl_end) as usize;
    let ram_start = core::ptr::addr_of!(__guest_ram_start) as usize;
    let len = tpl_end - tpl_start;
    // SAFETY: as `load_guest` — in-image template source, reserved guest-RAM destination far larger
    // than the template, non-overlapping. `ram_start` is 2 MiB-aligned so the blob's internal 0x800
    // alignment is preserved at runtime.
    unsafe {
        core::ptr::copy_nonoverlapping(tpl_start as *const u8, ram_start as *mut u8, len);
    }
    ram_start as u64
}

/// Copy the **disposable** guest template into guest RAM and return its `entry` guest-physical address
/// (M5 Arc 6).
fn load_guest_disposable() -> u64 {
    let tpl_start = core::ptr::addr_of!(__guest_disposable_tpl_start) as usize;
    let tpl_end = core::ptr::addr_of!(__guest_disposable_tpl_end) as usize;
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

/// Read `(ESR_EL2, FAR_EL2)` for a Stage-2 data abort (M5 Arc 3, MMIO). `FAR_EL2` holds the faulting
/// **guest VA**; the guest runs Stage-1 off (`SCTLR_EL1.M=0`, [`init_guest_el1`]), so VA == IPA and
/// `FAR_EL2` is the FULL faulting address — including the in-page register offset `HPFAR_EL2` lacks —
/// which is exactly what MMIO register decode needs (which device register was touched).
fn read_esr_far() -> (u64, u64) {
    let (esr, far): (u64, u64);
    // SAFETY: both RO EL2 system registers, readable at EL2; no memory effect.
    unsafe {
        asm!(
            "mrs {0}, esr_el2",
            "mrs {1}, far_el2",
            out(reg) esr,
            out(reg) far,
            options(nomem, nostack, preserves_flags),
        );
    }
    (esr, far)
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
        0x24 => handle_data_abort(frame, &mut uart), // MMIO trap-and-emulate, or an isolation probe
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

    // PSCI calls arrive via HVC with an SMC-convention function ID in x0 (M5 Arc 5c); route them to the
    // PSCI handler before the small internal test-`nr` dispatch below (no collision — PSCI FIDs are huge).
    if is_psci_fid(nr) {
        handle_psci(frame, uart);
        return;
    }

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
        NR_VIRTIO_ID => virtio_report_id(frame, uart), // M5 Arc 3: assert the mmio identity registers
        NR_VIRTIO_NEGOTIATED => virtio_report_negotiated(frame, uart), // assert VERSION_1 + FEATURES_OK
        NR_VIRTIO_FINAL => finish_virtio_console_test(uart), // -> ! (phase-5 → block phases)
        NR_BLK_ID => virtio_blk_report_id(frame, uart), // M5 Arc 4: assert the virtio-blk identity
        NR_BLK_NEGOTIATED => virtio_blk_report_negotiated(frame, uart), // assert VERSION_1 + FEATURES_OK
        NR_BLK_READ_REPORT => virtio_blk_report_read(frame, uart), // assert the read round-tripped
        NR_BLK_FINAL => finish_virtio_blk_test(uart), // -> ! (block phase → vGIC phase)
        NR_GIC_READY => gic::inject(GIC_TEST_INTID),  // M5 Arc 5a/b: inject a virtual interrupt now
        NR_GIC_REPORT => gic_report(frame, uart), // assert the guest acknowledged the right INTID
        NR_GIC_FINAL => finish_gic_test(uart),    // -> ! (vGIC poll phase → async phase)
        NR_GIC_ASYNC_REPORT => gic_async_report(frame, uart), // M5 Arc 5b: assert vectored delivery
        NR_GIC_ASYNC_FINAL => finish_gic_async_test(uart), // -> ! (async phase → timer phase)
        NR_TIMER_REPORT => timer_report(frame, uart), // M5 Arc 5b: assert the virtual timer fired
        NR_TIMER_FINAL => finish_timer_test(uart), // -> ! (timer phase → PSCI phase)
        NR_PSCI_REPORT => psci_report(frame, uart), // M5 Arc 5c: assert the guest read the PSCI version
        NR_TIMER_IRQ_REPORT => timer_irq_report(frame, uart), // M5 Arc 5d: assert the tick was taken
        NR_TIMER_IRQ_FINAL => finish_timer_irq_test(uart), // -> ! (timer-tick phase → thesis phase)
        NR_THESIS_POS => thesis_pos_report(frame, uart), // M5 Arc 6: disposable own-write + probe report
        NR_THESIS_FINAL => finish_thesis_test(uart), // -> ! (thesis phase terminal — destroy + audit)
        other => {
            let _ = writeln!(uart, "baleen: guest HVC unknown nr={other}; halting");
            crate::park();
        }
    }
}

/// Route a guest **data abort** (`EC=0x24`): a fault in the virtio-mmio device window is **trap-and-
/// emulate** (M5 Arc 3); anything else is an isolation probe recorded by [`record_data_abort`] (Arcs
/// 5/0/2). The `FAR_EL2` window check is the discriminator (Stage-1 off ⇒ `FAR_EL2` is the full IPA).
fn handle_data_abort(frame: &mut GuestFrame, uart: &mut Pl011) {
    let (esr, far) = read_esr_far();
    if crate::virtio::in_mmio_window(far) {
        handle_mmio(frame, esr, far, uart);
    } else {
        record_data_abort(uart);
    }
}

/// **M5 Arc 3 — virtio-mmio trap-and-emulate.** Decode the data-abort syndrome (`ESR_EL2.ISS`: `ISV`
/// valid, `SAS` size, `SRT` target register, `WnR` direction) and the register offset (`FAR_EL2` −
/// [`crate::virtio::VIRTIO_MMIO_BASE`]), service the register in the device model, write any read
/// result back into the guest's saved register frame, and advance `ELR` past the faulting instruction.
/// A `QueueNotify` write triggers the backend's queue processing (wired in a later step).
fn handle_mmio(frame: &mut GuestFrame, esr: u64, far: u64, uart: &mut Pl011) {
    let iss = esr & 0x01ff_ffff; // ESR_EL2.ISS[24:0]
    let isv = (iss >> 24) & 1; // instruction syndrome valid
    if isv == 0 {
        // No decoded syndrome (e.g. a non-GP-register or misaligned access) — we cannot emulate it.
        let _ = writeln!(
            uart,
            "baleen: virtio-mmio abort at 0x{far:016x} without ISV (undecodable access); halting"
        );
        crate::park();
    }
    // `FnV` (ISS[10]) — if the FAR is not valid we cannot trust the register offset; halt loudly rather
    // than emulate at a garbage address. `SAS` (ISS[23:22]) — the virtio-mmio register file is 32-bit;
    // a byte/half/dword access would be mis-emulated at word width, so refuse it (a real Linux driver
    // reads the registers word-wide, but the config space may differ — the Arc-5 capstone widens this).
    if (iss >> 10) & 1 != 0 {
        let _ = writeln!(
            uart,
            "baleen: virtio-mmio abort with FnV (FAR invalid); halting"
        );
        crate::park();
    }
    let sas = (iss >> 22) & 0b11;
    if sas != 0b10 {
        let _ = writeln!(
            uart,
            "baleen: virtio-mmio abort at 0x{far:016x} with non-word access size (SAS={sas}); halting"
        );
        crate::park();
    }
    let srt = ((iss >> 16) & 0x1f) as usize; // target GP register (31 = XZR/discard)
    let wnr = (iss >> 6) & 1 != 0; // write-not-read
    let offset = far - crate::virtio::VIRTIO_MMIO_BASE;

    // Route to whichever virtio device the current phase installed at this window (console in Arc 3,
    // block in Arc 4). Only one is live at a time — the phases run sequentially.
    let active = active_virtio();
    if active == ActiveVirtio::None {
        let _ = writeln!(
            uart,
            "baleen: virtio-mmio access with no active device; halting"
        );
        crate::park();
    }
    if wnr {
        // A store: the value is the guest's source register (XZR reads as 0).
        let value = if srt < 31 { frame.x[srt] } else { 0 } as u32;
        let notify = match active {
            ActiveVirtio::Console => virtio_dev().mmio_write(offset, value),
            ActiveVirtio::Blk => blk_dev().mmio_write(offset, value),
            ActiveVirtio::None => crate::park(),
        };
        if notify {
            // The queue kick — dispatched to the active device's backend (both grant-gated).
            match active {
                ActiveVirtio::Console => handle_virtio_notify(uart),
                ActiveVirtio::Blk => handle_virtio_blk_notify(uart),
                ActiveVirtio::None => crate::park(),
            }
        }
    } else {
        // A load: service the register and write the result back into the guest's saved frame.
        let value = match active {
            ActiveVirtio::Console => virtio_dev().mmio_read(offset),
            ActiveVirtio::Blk => blk_dev().mmio_read(offset),
            ActiveVirtio::None => crate::park(),
        } as u64;
        if srt < 31 {
            frame.x[srt] = value;
        }
    }
    advance_elr_past_fault();
}

/// Recover the model frame (`Mfn`) a guest IPA lands in, from the shared data-region layout
/// (`frame_ipa(m) = DATA_IPA_BASE + m*FRAME_SIZE`). `None` if the IPA is below the data region.
fn gpa_to_mfn(gpa: u64) -> Option<Mfn> {
    gpa.checked_sub(stage2::DATA_IPA_BASE)
        .map(|off| (off / stage2::FRAME_SIZE) as Mfn)
}

/// **The grant gate — the heart of Arc 3.** Authorize a backend access of `len` bytes at guest IPA
/// `gpa` (writability `writable`) against the proven grant table: the frame the access lands in must be
/// GRANTED by the guest to the backend (dom0) at the needed permission. Refuses (records the negative
/// witness, returns `false`) an access to a frame the guest did not grant, or one that would straddle a
/// frame boundary (a single grant authorizes a single frame). This is what makes the ring a *grant*:
/// the descriptor addresses are untrusted guest data, and every one the backend dereferences is checked.
fn backend_authorize(
    hv: &Hypervisor,
    gpa: u64,
    len: u64,
    writable: bool,
    uart: &mut Pl011,
) -> bool {
    let Some(mfn) = gpa_to_mfn(gpa) else {
        let _ = writeln!(
            uart,
            "baleen: virtio backend REFUSED access at IPA 0x{gpa:016x} (below the data region); not a granted frame"
        );
        VIRTIO_UNGRANTED_REFUSED.store(true, Ordering::Relaxed);
        return false;
    };
    // A single frame grant authorizes a single frame; reject an access that crosses the boundary.
    if (gpa & (stage2::FRAME_SIZE - 1)) + len > stage2::FRAME_SIZE {
        let _ = writeln!(
            uart,
            "baleen: virtio backend REFUSED access at IPA 0x{gpa:016x} len {len} (crosses a frame boundary)"
        );
        VIRTIO_UNGRANTED_REFUSED.store(true, Ordering::Relaxed);
        return false;
    }
    if !hv
        .grant()
        .authorizes(VIRTIO_DOM, VIRTIO_BACKEND, mfn as Frame, writable)
    {
        let _ = writeln!(
            uart,
            "baleen: virtio backend REFUSED un-granted access to Mfn {mfn} (IPA 0x{gpa:016x}, writable={writable}) — the ring is a grant"
        );
        VIRTIO_UNGRANTED_REFUSED.store(true, Ordering::Relaxed);
        return false;
    }
    true
}

/// Grant-checked backend **read** of `buf.len()` bytes from guest IPA `gpa` (via the fence's
/// `GuestMemory`, host-PA direct). Returns `false` (leaving `buf` untouched) if the grant refuses.
fn backend_read(hv: &Hypervisor, gpa: u64, buf: &mut [u8], uart: &mut Pl011) -> bool {
    backend_authorize(hv, gpa, buf.len() as u64, false, uart) && GuestMem.read(gpa, buf).is_ok()
}

/// Grant-checked backend **write** of `buf` to guest IPA `gpa`. Requires a *writable* grant. Returns
/// `false` (writing nothing) if the grant refuses.
fn backend_write(hv: &Hypervisor, gpa: u64, buf: &[u8], uart: &mut Pl011) -> bool {
    backend_authorize(hv, gpa, buf.len() as u64, true, uart) && {
        let mut gm = GuestMem;
        gm.write(gpa, buf).is_ok()
    }
}

/// Grant-checked reads of the little-endian integer types the virtqueue is laid out in.
fn backend_read_u16(hv: &Hypervisor, gpa: u64, uart: &mut Pl011) -> Option<u16> {
    let mut b = [0u8; 2];
    backend_read(hv, gpa, &mut b, uart).then(|| u16::from_le_bytes(b))
}
fn backend_read_u32(hv: &Hypervisor, gpa: u64, uart: &mut Pl011) -> Option<u32> {
    let mut b = [0u8; 4];
    backend_read(hv, gpa, &mut b, uart).then(|| u32::from_le_bytes(b))
}
fn backend_read_u64(hv: &Hypervisor, gpa: u64, uart: &mut Pl011) -> Option<u64> {
    let mut b = [0u8; 8];
    backend_read(hv, gpa, &mut b, uart).then(|| u64::from_le_bytes(b))
}

/// **M5 Arc 3 — the queue kick (the backend).** The driver wrote `QueueNotify`; the backend, acting as
/// dom0, walks the TX split-virtqueue and drains completed buffers to the PL011 console. EVERY guest-
/// memory access — the available ring, the descriptor table, the data buffer, and the used ring it
/// writes back — is authorized by [`backend_authorize`] against the guest's grant. The device is not
/// live until the driver finished the handshake (`DRIVER_OK`) and marked the queue ready.
fn handle_virtio_notify(uart: &mut Pl011) {
    use crate::virtio::{
        VIRTQ_AVAIL_IDX_OFF, VIRTQ_AVAIL_RING_OFF, VIRTQ_DESC_SIZE, VIRTQ_USED_ELEM_SIZE,
        VIRTQ_USED_IDX_OFF, VIRTQ_USED_RING_OFF,
    };
    // SAFETY: single-CPU, non-nested handler; the Hypervisor was built before the guest ran.
    let hv = match unsafe { (*GUEST_HV.0.get()).as_ref() } {
        Some(hv) => hv,
        None => crate::park(),
    };
    let dev = virtio_dev();
    if !dev.queue_live() {
        let _ = writeln!(
            uart,
            "baleen: virtio QueueNotify before the queue is live (status=0x{:02x} ready={}); ignoring",
            dev.status, dev.queue_ready
        );
        return;
    }
    let num = dev.queue_num as u16;
    if num == 0 {
        return;
    }

    // How many buffers has the driver made available?
    let Some(avail_idx) = backend_read_u16(hv, dev.queue_driver + VIRTQ_AVAIL_IDX_OFF, uart) else {
        return;
    };

    while dev.last_avail_idx != avail_idx {
        // The head descriptor index for this available entry.
        let slot = (dev.last_avail_idx % num) as u64;
        let Some(head) =
            backend_read_u16(hv, dev.queue_driver + VIRTQ_AVAIL_RING_OFF + slot * 2, uart)
        else {
            return;
        };

        // The descriptor: addr / len / flags (we handle a single device-readable buffer, no chaining).
        let desc = dev.queue_desc + head as u64 * VIRTQ_DESC_SIZE;
        let (Some(addr), Some(len)) = (
            backend_read_u64(hv, desc, uart),
            backend_read_u32(hv, desc + 8, uart),
        ) else {
            return;
        };

        // Drain the buffer to the console — the descriptor's address is untrusted, so this read is
        // grant-checked like every other. A refusal aborts this buffer (the bytes never reach the
        // console) but still retires it on the used ring, so the ring stays consistent.
        let written = backend_drain_to_console(hv, addr, len, uart);

        // Retire the buffer on the used ring: used.ring[used_idx % num] = { id: head, len: written }.
        let used_slot = (dev.used_idx % num) as u64;
        let elem = dev.queue_device + VIRTQ_USED_RING_OFF + used_slot * VIRTQ_USED_ELEM_SIZE;
        let _ = backend_write(hv, elem, &(head as u32).to_le_bytes(), uart);
        let _ = backend_write(hv, elem + 4, &written.to_le_bytes(), uart);
        dev.used_idx = dev.used_idx.wrapping_add(1);
        let _ = backend_write(
            hv,
            dev.queue_device + VIRTQ_USED_IDX_OFF,
            &dev.used_idx.to_le_bytes(),
            uart,
        );

        dev.last_avail_idx = dev.last_avail_idx.wrapping_add(1);
    }

    // Raise a used-buffer notification (bit 0); a real driver reads InterruptStatus + ACKs it.
    dev.interrupt_status |= 1;
    VIRTIO_DRAINED_OK.store(true, Ordering::Relaxed);
}

/// Drain `len` bytes of a granted TX buffer at guest IPA `addr` to the PL011 console, one grant-checked
/// chunk at a time. Returns the number of bytes actually written (0 if the grant refused the buffer —
/// the un-granted negative). Bounds `len` to a sane maximum so a corrupt descriptor can't spin.
fn backend_drain_to_console(hv: &Hypervisor, addr: u64, len: u32, uart: &mut Pl011) -> u32 {
    const MAX_TX: u32 = 256; // one console line; a larger buffer would chunk, deferred
    let len = len.min(MAX_TX);
    let mut buf = [0u8; MAX_TX as usize];
    let slice = &mut buf[..len as usize];
    if !backend_read(hv, addr, slice, uart) {
        return 0; // refused (un-granted buffer) — nothing reaches the console
    }
    let _ = writeln!(
        uart,
        "baleen: virtio-console backend: draining {len} bytes from the granted ring (grant-authorized)"
    );
    for &byte in slice.iter() {
        uart.put(byte);
    }
    len
}

/// One split-virtqueue descriptor, read (grant-checked) from the guest's descriptor table (M5 Arc 4).
struct BlkDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

/// Grant-checked read of descriptor `index` from the guest's descriptor table at `desc_table`. `None`
/// if the index is out of the negotiated ring or any field access is refused (an un-granted ring).
fn backend_read_desc(
    hv: &Hypervisor,
    desc_table: u64,
    index: u16,
    num: u16,
    uart: &mut Pl011,
) -> Option<BlkDesc> {
    if index >= num {
        return None; // a chain index outside the negotiated ring — malformed
    }
    let d = desc_table + index as u64 * crate::virtio::VIRTQ_DESC_SIZE;
    Some(BlkDesc {
        addr: backend_read_u64(hv, d, uart)?,
        len: backend_read_u32(hv, d + 8, uart)?,
        flags: backend_read_u16(hv, d + 12, uart)?,
        next: backend_read_u16(hv, d + 14, uart)?,
    })
}

/// **M5 Arc 4 — the block queue kick (the backend).** The driver wrote `QueueNotify`; the backend, acting
/// as dom0, walks each available request — a **descriptor chain** { header → data → status } — and serves
/// it against the copy-on-write disk. EVERY guest-memory access (ring, each descriptor, the header, the
/// data buffer, the status byte, the used ring) is grant-authorized exactly as Arc 3; the new content is
/// the chain walk, the device-writable data buffer of a read, and the CoW disk.
fn handle_virtio_blk_notify(uart: &mut Pl011) {
    use crate::virtio::{
        VIRTQ_AVAIL_IDX_OFF, VIRTQ_AVAIL_RING_OFF, VIRTQ_USED_ELEM_SIZE, VIRTQ_USED_IDX_OFF,
        VIRTQ_USED_RING_OFF,
    };
    // SAFETY: single-CPU, non-nested handler; the Hypervisor was built before the guest ran.
    let hv = match unsafe { (*GUEST_HV.0.get()).as_ref() } {
        Some(hv) => hv,
        None => crate::park(),
    };
    let dev = blk_dev();
    if !dev.queue_live() {
        let _ = writeln!(
            uart,
            "baleen: virtio-blk QueueNotify before the queue is live (status=0x{:02x} ready={}); ignoring",
            dev.status, dev.queue_ready
        );
        return;
    }
    let num = dev.queue_num as u16;
    if num == 0 {
        return;
    }
    let Some(avail_idx) = backend_read_u16(hv, dev.queue_driver + VIRTQ_AVAIL_IDX_OFF, uart) else {
        return;
    };
    while dev.last_avail_idx != avail_idx {
        let slot = (dev.last_avail_idx % num) as u64;
        let Some(head) =
            backend_read_u16(hv, dev.queue_driver + VIRTQ_AVAIL_RING_OFF + slot * 2, uart)
        else {
            return;
        };
        process_blk_request(hv, dev.queue_desc, num, head, uart);

        // Retire the request on the used ring (grant-checked, like the console). virtio-blk drivers do
        // not rely on the reported `len` for the status byte, so 0 is sufficient for the synthetic guest.
        let used_slot = (dev.used_idx % num) as u64;
        let elem = dev.queue_device + VIRTQ_USED_RING_OFF + used_slot * VIRTQ_USED_ELEM_SIZE;
        let _ = backend_write(hv, elem, &(head as u32).to_le_bytes(), uart);
        let _ = backend_write(hv, elem + 4, &0u32.to_le_bytes(), uart);
        dev.used_idx = dev.used_idx.wrapping_add(1);
        let _ = backend_write(
            hv,
            dev.queue_device + VIRTQ_USED_IDX_OFF,
            &dev.used_idx.to_le_bytes(),
            uart,
        );
        dev.last_avail_idx = dev.last_avail_idx.wrapping_add(1);
    }
    dev.interrupt_status |= 1;
}

/// Service one virtio-blk request chain for the current tenant: parse the { header → data → status }
/// descriptors (each grant-checked), then serve a read (CoW-read the sector → grant-**write** the guest's
/// device-writable buffer) or a write (grant-**read** the buffer → CoW-**write** the tenant's overlay,
/// never the template), and write the status byte. A grant refusal on the data buffer is the negative —
/// the request errors and no bytes cross ([`BLK_UNGRANTED_REFUSED`] records the cause).
fn process_blk_request(hv: &Hypervisor, desc_table: u64, num: u16, head: u16, uart: &mut Pl011) {
    use crate::blk::{
        BLK_HDR_SECTOR_OFF, BLK_HDR_SIZE, DISK_SECTORS, SECTOR_SIZE, VIRTIO_BLK_S_IOERR,
        VIRTIO_BLK_S_OK, VIRTIO_BLK_T_IN, VIRTIO_BLK_T_OUT, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    };
    let tenant = BLK_TENANT.load(Ordering::Relaxed) as usize;
    let disk = blk_disk();

    // desc0: the request header (device-readable), chained to the data descriptor.
    let Some(d0) = backend_read_desc(hv, desc_table, head, num, uart) else {
        return;
    };
    if d0.flags & VIRTQ_DESC_F_NEXT == 0 || (d0.len as u64) < BLK_HDR_SIZE {
        let _ = writeln!(
            uart,
            "baleen: virtio-blk malformed request: header not chained or under-sized"
        );
        return;
    }
    let (Some(typ), Some(sector64)) = (
        backend_read_u32(hv, d0.addr, uart),
        backend_read_u64(hv, d0.addr + BLK_HDR_SECTOR_OFF, uart),
    ) else {
        return;
    };
    // desc1: the data buffer, chained to the status descriptor.
    let Some(d1) = backend_read_desc(hv, desc_table, d0.next, num, uart) else {
        return;
    };
    if d1.flags & VIRTQ_DESC_F_NEXT == 0 {
        let _ = writeln!(
            uart,
            "baleen: virtio-blk malformed request: data not chained"
        );
        return;
    }

    let sector = sector64 as usize;
    let n = (d1.len as usize).min(SECTOR_SIZE);
    // The data descriptor's direction must match the request: a read (T_IN) delivers into a
    // device-WRITABLE buffer; a write (T_OUT) sources a device-READABLE one. Refuse a mismatch loudly
    // rather than DMA in the wrong direction (a real driver always sets these consistently).
    let data_writable = d1.flags & VIRTQ_DESC_F_WRITE != 0;
    let direction_ok = match typ {
        VIRTIO_BLK_T_IN => data_writable,
        VIRTIO_BLK_T_OUT => !data_writable,
        _ => false,
    };
    // desc2: the status byte (device-writable).
    let Some(d2) = backend_read_desc(hv, desc_table, d1.next, num, uart) else {
        return;
    };

    let mut status = VIRTIO_BLK_S_OK;
    if sector >= DISK_SECTORS || !direction_ok {
        status = VIRTIO_BLK_S_IOERR;
    } else {
        match typ {
            VIRTIO_BLK_T_IN => {
                // The data buffer is device-WRITABLE: authorize a WRITE into guest memory, then DMA the
                // (CoW-read) sector into it. A refusal is the negative — nothing crosses.
                if !backend_authorize(hv, d1.addr, n as u64, true, uart) {
                    BLK_UNGRANTED_REFUSED.store(true, Ordering::Relaxed);
                    status = VIRTIO_BLK_S_IOERR;
                } else {
                    let sector_data = *disk.read(tenant, sector); // CoW: overlay if written, else template
                    let mut gm = GuestMem;
                    if gm.write(d1.addr, &sector_data[..n]).is_ok() {
                        // Echo the served bytes: a positive witness (the template marker) — and, were
                        // isolation ever broken, the forbidden poison would surface here (FORBIDDEN guard).
                        let _ = writeln!(
                            uart,
                            "baleen: virtio-blk READ served sector {sector} to tenant {tenant} ({n} bytes, grant-authorized)"
                        );
                        // Echo up to the sector's NUL terminator (the markers are NUL-padded), so a leak
                        // of the forbidden poison would still surface without printing 474 pad bytes.
                        for &b in &sector_data[..n] {
                            if b == 0 {
                                break;
                            }
                            uart.put(b);
                        }
                    } else {
                        status = VIRTIO_BLK_S_IOERR;
                    }
                }
            }
            VIRTIO_BLK_T_OUT => {
                // The data buffer is device-READABLE: authorize a READ of guest memory, then CoW-write
                // the tenant's OVERLAY (never the template).
                if !backend_authorize(hv, d1.addr, n as u64, false, uart) {
                    BLK_UNGRANTED_REFUSED.store(true, Ordering::Relaxed);
                    status = VIRTIO_BLK_S_IOERR;
                } else {
                    let mut buf = [0u8; SECTOR_SIZE];
                    if GuestMem.read(d1.addr, &mut buf[..n]).is_ok() {
                        disk.write(tenant, sector, &buf[..n]);
                        let _ = writeln!(
                            uart,
                            "baleen: virtio-blk WRITE by tenant {tenant} landed in its CoW overlay (sector {sector}; template untouched)"
                        );
                    } else {
                        status = VIRTIO_BLK_S_IOERR;
                    }
                }
            }
            _ => status = VIRTIO_BLK_S_IOERR,
        }
    }
    // The status byte is device-writable — grant-checked like every other guest-memory access.
    let _ = backend_write(hv, d2.addr, &[status], uart);
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

    // M5 Arc 3: with concurrent isolation confirmed, drive phase 5 — the virtio-mmio console (the ring
    // IS a proven grant). Never returns (it ends the boot, chaining the selftest BRK as the last act).
    // A broken isolation baseline parks rather than layering a fresh phase on it.
    if iso_ok {
        begin_virtio_console_phase5(uart);
    }
    crate::park();
}

/// The deliberate-fault self-test (moved to the boot's LAST terminal each arc): a `BRK` at EL2 vectors
/// to slot 4, which the diagnostic handler catches + decodes (`EC=0x3c`) — keeps that Arc-2 witness
/// alive in the same boot. Only under `--features selftest`; a no-op otherwise. Every phase terminal
/// that may be the boot's last act calls this before `park`.
fn selftest_brk(uart: &mut Pl011) {
    #[cfg(feature = "selftest")]
    {
        let _ = writeln!(uart, "baleen: exception self-test — executing BRK #0");
        // SAFETY: `BRK` raises a synchronous exception taken to EL2; the installed handler reports+halts.
        unsafe { asm!("brk #0") };
        let _ = writeln!(uart, "baleen: BUG — returned from the BRK self-test");
    }
    let _ = uart;
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

/// **M5 Arc 3 — assert the virtio-mmio identity registers.** The driver read Magic (`x1`), Version
/// (`x2`), DeviceID (`x3`), VendorID (`x4`) through the trap-and-emulated register file; confirm each
/// matches the device model's constant. A checkpoint (records + resumes), not terminal.
fn virtio_report_id(frame: &mut GuestFrame, uart: &mut Pl011) {
    let magic = frame.x[1] as u32;
    let version = frame.x[2] as u32;
    let device = frame.x[3] as u32;
    let vendor = frame.x[4] as u32;
    let ok = magic == crate::virtio::MAGIC
        && version == crate::virtio::VERSION_V2
        && device == crate::virtio::DEVICE_ID_CONSOLE
        && vendor == crate::virtio::VENDOR;
    VIRTIO_ID_OK.store(ok, Ordering::Relaxed);
    if ok {
        let _ = writeln!(
            uart,
            "baleen: virtio-mmio device identified: magic=\"virt\" version=2 id=3 (console) via trap-and-emulate"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: virtio-mmio identify MISMATCH: magic=0x{magic:08x} version={version} id={device} vendor=0x{vendor:08x}"
        );
    }
}

/// **M5 Arc 3 — assert the device negotiation.** The driver walked the `Status` handshake
/// (ACKNOWLEDGE → DRIVER → FEATURES_OK) and negotiated features; confirm it saw `VIRTIO_F_VERSION_1`
/// offered in device-features word 1 (`x1`) and that the device left `FEATURES_OK` set in the `Status`
/// it read back (`x2`) — i.e. the device accepted the driver's feature selection. A checkpoint.
fn virtio_report_negotiated(frame: &mut GuestFrame, uart: &mut Pl011) {
    use crate::virtio::{
        STATUS_ACKNOWLEDGE, STATUS_DRIVER, STATUS_FEATURES_OK, VERSION_1_WORD1_MASK,
    };
    let dev_features_w1 = frame.x[1] as u32;
    let status = frame.x[2] as u32;
    let version_1_offered = dev_features_w1 & VERSION_1_WORD1_MASK != 0;
    // The device left the full handshake set after FEATURES_OK: ACKNOWLEDGE|DRIVER|FEATURES_OK, i.e. it
    // accepted the driver's feature selection (it did not clear FEATURES_OK to reject).
    let expected = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
    let features_ok_sticky = status & expected == expected;
    let ok = version_1_offered && features_ok_sticky;
    VIRTIO_NEGOTIATED_OK.store(ok, Ordering::Relaxed);
    if ok {
        let _ = writeln!(
            uart,
            "baleen: virtio negotiation OK: VIRTIO_F_VERSION_1 accepted, FEATURES_OK set (status=0x{status:02x})"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: virtio negotiation FAILED: version_1_offered={version_1_offered} features_ok={features_ok_sticky} (features_w1=0x{dev_features_w1:08x} status=0x{status:02x})"
        );
    }
}

/// **M5 Arc 3, phase 5 — the virtio-console run-loop.** Build a fresh `Hypervisor`, create the guest
/// domain, emit its Stage-2 (the guest image mapped; the virtio-mmio window deliberately UNMAPPED so
/// device accesses trap), and enter the driver guest. Its mmio accesses are trap-and-emulated
/// ([`handle_mmio`]); a `QueueNotify` (later steps) runs the grant-checked backend. Never returns.
fn begin_virtio_console_phase5(uart: &mut Pl011) -> ! {
    // A fresh Hypervisor: the isolation phase mutated the previous one. SAFETY: single-CPU, one-time
    // rebuild before the phase-5 guest runs; no handler is touching the cell.
    unsafe { *GUEST_HV.0.get() = Some(crate::build_hypervisor()) };
    let hv = match unsafe { (*GUEST_HV.0.get()).as_mut() } {
        Some(hv) => hv,
        None => crate::park(),
    };

    // dom0 creates the guest that runs the virtio-console driver.
    expect(
        hv,
        DOM0,
        HvCall::DomainCreate {
            target: VIRTIO_DOM,
            may_create: false,
        },
        "create virtio guest",
        uart,
    );

    // The guest allocates its page-table root + the two frames it will share: the virtqueue frame and
    // the TX buffer. It links both as writable leaves (so it can build the ring + write the message),
    // pins the root, and GRANTS both to dom0 — the virtqueue frame read-write (the backend writes the
    // used ring), the buffer read-only (the backend only reads the TX data). The ring IS a grant.
    for mfn in [F_VQ_ROOT, F_VQ, F_BUF, F_BUF_UNGRANTED] {
        expect(
            hv,
            VIRTIO_DOM,
            HvCall::P2mAllocate { mfn },
            "virtio alloc frame",
            uart,
        );
    }
    expect(
        hv,
        VIRTIO_DOM,
        HvCall::P2mPin {
            mfn: F_VQ_ROOT,
            level: PtLevel::L1,
        },
        "virtio pin root",
        uart,
    );
    // Link all three data frames writable (the guest writes each). It grants only F_VQ + F_BUF below;
    // F_BUF_UNGRANTED is deliberately NOT granted — a descriptor pointing at it is the step-4 negative.
    for (slot, child) in [(0u32, F_VQ), (1u32, F_BUF), (2u32, F_BUF_UNGRANTED)] {
        expect(
            hv,
            VIRTIO_DOM,
            HvCall::P2mLink {
                parent: F_VQ_ROOT,
                slot,
                child,
                writable: true,
                leaf: true,
            },
            "virtio link frame",
            uart,
        );
    }
    // The guest grants its ring + buffer to the backend (dom0). `gref` 0 = the virtqueue (RW), 1 = the
    // TX buffer (RO). These are the consent the backend's every access is checked against.
    expect(
        hv,
        VIRTIO_DOM,
        HvCall::GrantAccess {
            gref: 0 as GrantRef,
            grantee: VIRTIO_BACKEND,
            frame: F_VQ as Frame,
            readonly: false,
        },
        "virtio grant ring",
        uart,
    );
    expect(
        hv,
        VIRTIO_DOM,
        HvCall::GrantAccess {
            gref: 1 as GrantRef,
            grantee: VIRTIO_BACKEND,
            frame: F_BUF as Frame,
            readonly: true,
        },
        "virtio grant buffer",
        uart,
    );

    // Stage-2: the guest image (RO+X) and its two writable data leaves (the ring + buffer); the
    // virtio-mmio window is NOT mapped, so a device-register access faults to EL2 and is
    // trap-and-emulated.
    let vttbr = stage2::build_stage2_from_p2m(hv, VIRTIO_DOM, STAGE2_SET_SINGLE);
    let entry = load_guest5();
    let ram_end = core::ptr::addr_of!(__guest_ram_end) as u64;
    enable_stage2(vttbr);
    init_guest_el1(ram_end);
    {
        use hv_hal::VcpuOps;
        ArmVcpu.set_entry(entry);
    }
    IN_GUEST_HANDLER.store(false, Ordering::Relaxed);
    set_active_virtio(ActiveVirtio::Console); // route trapped mmio to the console register file
    let _ = writeln!(
        uart,
        "baleen: virtio-console phase — guest drives a virtio-mmio v2 console device (MMIO trap-and-emulate)"
    );
    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    enter_guest(exc_stack_top);
}

/// **M5 Arc 3, phase 5 terminal.** Assert the virtio-console matrix and finish (the boot's last act).
/// Step 1: the driver identified the device through the trap-and-emulated register file. Later steps
/// add the grant-checked TX path (guest bytes reach the console) and the negative (un-granted refused).
fn finish_virtio_console_test(uart: &mut Pl011) -> ! {
    let id_ok = VIRTIO_ID_OK.load(Ordering::Relaxed);
    let negotiated_ok = VIRTIO_NEGOTIATED_OK.load(Ordering::Relaxed);
    let drained_ok = VIRTIO_DRAINED_OK.load(Ordering::Relaxed);
    // The negative: the backend refused the descriptor pointing at the un-granted frame (so the secret
    // never reached the console). This is the diamond — the ring is a grant, not a hole.
    let refused_ok = VIRTIO_UNGRANTED_REFUSED.load(Ordering::Relaxed);
    if id_ok && negotiated_ok && drained_ok && refused_ok {
        let _ = writeln!(
            uart,
            "baleen: VIRTIO CONSOLE TEST PASSED — granted bytes delivered, un-granted access refused (the ring is a proven grant)"
        );
        // M5 Arc 4: the ring is a proven grant → now the DISK is a CoW template. Chain into the
        // virtio-blk phases; the last one ends the boot (running the deliberate-fault selftest).
        begin_virtio_blk_phase6(uart); // never returns
    }
    let _ = writeln!(
        uart,
        "baleen: VIRTIO CONSOLE TEST FAILED (id_ok={id_ok} negotiated_ok={negotiated_ok} drained_ok={drained_ok} refused_ok={refused_ok})"
    );
    crate::park();
}

/// **M5 Arc 4** — the driver reported the four virtio-blk identity registers (`x1`=Magic..`x4`=VendorID);
/// assert them (`DeviceID` = 2, block). A checkpoint (resumes the guest).
fn virtio_blk_report_id(frame: &mut GuestFrame, uart: &mut Pl011) {
    use crate::blk::DEVICE_ID_BLK;
    use crate::virtio::{MAGIC, VENDOR, VERSION_V2};
    let magic = frame.x[1] as u32;
    let version = frame.x[2] as u32;
    let device = frame.x[3] as u32;
    let vendor = frame.x[4] as u32;
    let ok = magic == MAGIC && version == VERSION_V2 && device == DEVICE_ID_BLK && vendor == VENDOR;
    BLK_ID_OK.store(ok, Ordering::Relaxed);
    if ok {
        let _ = writeln!(
            uart,
            "baleen: virtio-blk device identified: magic=\"virt\" version=2 id=2 (block) via trap-and-emulate"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: virtio-blk identity MISMATCH (magic=0x{magic:08x} version={version} id={device} vendor=0x{vendor:08x})"
        );
    }
}

/// **M5 Arc 4** — the driver reported negotiation (`x1`=device features word 1, `x2`=Status readback);
/// assert `VIRTIO_F_VERSION_1` was offered+accepted and FEATURES_OK stuck. A checkpoint.
fn virtio_blk_report_negotiated(frame: &mut GuestFrame, uart: &mut Pl011) {
    use crate::virtio::{STATUS_FEATURES_OK, VERSION_1_WORD1_MASK};
    let dev_features_w1 = frame.x[1] as u32;
    let status = frame.x[2] as u32;
    let version_1 = dev_features_w1 & VERSION_1_WORD1_MASK != 0;
    let features_ok = status & STATUS_FEATURES_OK != 0;
    let ok = version_1 && features_ok;
    BLK_NEGOTIATED_OK.store(ok, Ordering::Relaxed);
    if ok {
        let _ = writeln!(
            uart,
            "baleen: virtio-blk negotiation OK: VIRTIO_F_VERSION_1 accepted, FEATURES_OK set (status=0x{status:02x})"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: virtio-blk negotiation FAILED (version_1={version_1} features_ok={features_ok})"
        );
    }
}

/// The first 8 bytes of the template marker as a little-endian `u64` — what a clean read of sector 0
/// must round-trip back through the guest's data buffer (the guest does `ldr x1, [data]`).
fn blk_template_prefix() -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&BLK_TEMPLATE_MARKER[..8]);
    u64::from_le_bytes(b)
}

/// **M5 Arc 4** — the driver reported the first 8 bytes it read back from the (device-written) data
/// buffer (`x1`); assert they equal the template seed. For tenant 0 this witnesses "a clean sector reads
/// the template"; for tenant 1 it witnesses **overlay-isolation** (it read the template pristine, not
/// tenant 0's poison). A checkpoint.
fn virtio_blk_report_read(frame: &mut GuestFrame, uart: &mut Pl011) {
    let reported = frame.x[1];
    let tenant = BLK_TENANT.load(Ordering::Relaxed) as usize;
    let ok = reported == blk_template_prefix();
    if ok {
        BLK_READ_TEMPLATE_OK[tenant].store(true, Ordering::Relaxed);
        let _ = writeln!(
            uart,
            "baleen: virtio-blk read round-trip OK: tenant {tenant} read sector 0 = the pristine template"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: virtio-blk read round-trip MISMATCH: tenant {tenant} got 0x{reported:016x} (expected the template)"
        );
    }
}

/// **M5 Arc 4, block phase terminal.** Phase 6 (tenant 0): after its read/write/negative, check
/// template-immutability (HV-side) and chain into phase 7 (the second tenant). Phase 7 (tenant 1): assert
/// the whole block matrix — identity, negotiation, both tenants' template reads, template-immutability,
/// overlay-isolation (distinct overlays), and the grant negative — then finish the boot.
fn finish_virtio_blk_test(uart: &mut Pl011) -> ! {
    let tenant = BLK_TENANT.load(Ordering::Relaxed);
    if tenant == 0 {
        // Phase 6 done: tenant 0 read the template, wrote poison, and issued the un-granted negative.
        check_template_immutability(uart);
        begin_virtio_blk_phase7(uart); // never returns — the second tenant reads the shared template
    }

    // Phase 7 (tenant 1) done — assert the full diamond.
    let id_ok = BLK_ID_OK.load(Ordering::Relaxed);
    let negotiated_ok = BLK_NEGOTIATED_OK.load(Ordering::Relaxed);
    let t0_read_ok = BLK_READ_TEMPLATE_OK[0].load(Ordering::Relaxed);
    let t1_read_ok = BLK_READ_TEMPLATE_OK[1].load(Ordering::Relaxed);
    let write_isolated_ok = BLK_WRITE_ISOLATED_OK.load(Ordering::Relaxed);
    let refused_ok = BLK_UNGRANTED_REFUSED.load(Ordering::Relaxed);
    // The LIVE overlay-isolation discriminators are `t1_read_ok` (tenant 1 round-tripped the *template*,
    // not tenant 0's poison, which persists in `overlay[0]` during tenant 1's phase) plus the absent
    // `POISON` forbidden-marker. `overlays_distinct` below is a by-construction *structural* assertion
    // (the overlays are distinct rows of a fixed array — it cannot fail without rewriting the struct); it
    // documents the "distinct storage" clause of the property but does not by itself discriminate a leak.
    let disk = blk_disk();
    let overlays_distinct = !core::ptr::eq(disk.overlay_ptr(0, 0), disk.overlay_ptr(1, 0));

    if id_ok
        && negotiated_ok
        && t0_read_ok
        && t1_read_ok
        && write_isolated_ok
        && refused_ok
        && overlays_distinct
    {
        // Printed ONLY when the whole matrix holds: a write hit the overlay (template pristine), a second
        // tenant read the template pristine over distinct overlays, and the un-granted access was refused.
        let _ = writeln!(
            uart,
            "baleen: VIRTIO-BLK TEST PASSED — writes hit the CoW overlay, template immutable, peer overlay isolated, un-granted access refused"
        );
        // M5 Arc 5a: with the device arcs proven, drive the vGIC phase — give a guest interrupts (the
        // first step toward a real Linux guest). Never returns (it ends the boot at the vGIC terminal).
        begin_gic_phase(uart);
    } else {
        let _ = writeln!(
            uart,
            "baleen: VIRTIO-BLK TEST FAILED (id_ok={id_ok} negotiated_ok={negotiated_ok} t0_read_ok={t0_read_ok} t1_read_ok={t1_read_ok} write_isolated_ok={write_isolated_ok} refused_ok={refused_ok} overlays_distinct={overlays_distinct})"
        );
    }
    selftest_brk(uart);
    crate::park();
}

/// **M5 Arc 5a** — the guest reported the INTID it acknowledged (`x1`); assert it equals the injected
/// [`GIC_TEST_INTID`]. A checkpoint (resumes the guest).
fn gic_report(frame: &mut GuestFrame, uart: &mut Pl011) {
    let intid = frame.x[1] as u32;
    let ok = intid == GIC_TEST_INTID;
    GIC_INJECT_OK.store(ok, Ordering::Relaxed);
    if ok {
        let _ = writeln!(
            uart,
            "baleen: vGIC injection OK: guest acknowledged the injected virtual interrupt (INTID {intid}) via ICC_IAR1_EL1"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: vGIC injection MISMATCH: guest acknowledged INTID {intid} (expected {GIC_TEST_INTID})"
        );
    }
}

/// **M5 Arc 5a, vGIC poll phase terminal.** Assert the injection reached the CPU interface, then chain
/// into the async-delivery phase (5b).
fn finish_gic_test(uart: &mut Pl011) -> ! {
    if GIC_INJECT_OK.load(Ordering::Relaxed) {
        let _ = writeln!(
            uart,
            "baleen: VGIC TEST PASSED — a virtual interrupt injected via the list registers reached the guest's CPU interface"
        );
        // M5 Arc 5b: prove ASYNC vectored delivery (the guest takes the IRQ at its EL1 vector). Never
        // returns (it ends the boot at the async terminal).
        begin_gic_async_phase(uart);
    }
    let _ = writeln!(
        uart,
        "baleen: VGIC TEST FAILED — injected interrupt not acknowledged"
    );
    crate::park();
}

/// **M5 Arc 5b** — the guest reported (from its EL1 IRQ vector) the INTID it took asynchronously; assert
/// it equals the injected [`GIC_TEST_INTID`]. A checkpoint.
fn gic_async_report(frame: &mut GuestFrame, uart: &mut Pl011) {
    let intid = frame.x[1] as u32;
    let ok = intid == GIC_TEST_INTID;
    GIC_ASYNC_OK.store(ok, Ordering::Relaxed);
    if ok {
        let _ = writeln!(
            uart,
            "baleen: vGIC async-delivery OK: guest TOOK the injected virtual interrupt (INTID {intid}) at its EL1 IRQ vector"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: vGIC async-delivery MISMATCH: guest took INTID {intid} (expected {GIC_TEST_INTID})"
        );
    }
}

/// **M5 Arc 5b, async-delivery phase terminal.** Assert vectored delivery, then chain into the
/// virtual-timer phase.
fn finish_gic_async_test(uart: &mut Pl011) -> ! {
    if GIC_ASYNC_OK.load(Ordering::Relaxed) {
        let _ = writeln!(
            uart,
            "baleen: VGIC ASYNC TEST PASSED — a virtual interrupt was delivered asynchronously to the guest's EL1 vector"
        );
        // M5 Arc 5b: prove the guest can use the virtual timer for timekeeping. Never returns.
        begin_timer_phase(uart);
    }
    let _ = writeln!(
        uart,
        "baleen: VGIC ASYNC TEST FAILED — interrupt not delivered to the guest vector"
    );
    crate::park();
}

/// **M5 Arc 5b** — the guest reported the virtual timer fired (`x1` = `CNTV_CTL` with `ISTATUS`, `x2` =
/// count before, `x3` = count after); assert the compare condition fired and the counter advanced. A
/// checkpoint.
fn timer_report(frame: &mut GuestFrame, uart: &mut Pl011) {
    let ctl = frame.x[1];
    let before = frame.x[2];
    let after = frame.x[3];
    let istatus = ctl & (1 << 2) != 0;
    let advanced = after > before;
    let ok = istatus && advanced;
    TIMER_OK.store(ok, Ordering::Relaxed);
    if ok {
        let _ = writeln!(
            uart,
            "baleen: virtual timer OK: CNTVCT advanced ({before} -> {after}) and the compare condition fired (ISTATUS set)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: virtual timer FAILED (istatus={istatus} advanced={advanced} before={before} after={after})"
        );
    }
}

/// **M5 Arc 5b, virtual-timer phase terminal.** Assert the timer worked, then chain into the PSCI phase.
fn finish_timer_test(uart: &mut Pl011) -> ! {
    if TIMER_OK.load(Ordering::Relaxed) {
        let _ = writeln!(
            uart,
            "baleen: TIMER TEST PASSED — the guest used the virtual timer (CNTVCT + a programmed deadline) for timekeeping"
        );
        // M5 Arc 5c: prove PSCI (version query + power off). Never returns.
        begin_psci_phase(uart);
    }
    let _ = writeln!(
        uart,
        "baleen: TIMER TEST FAILED — the virtual timer did not fire"
    );
    crate::park();
}

/// Whether `nr` is a PSCI function ID (SMC Calling Convention): the Standard Secure/Power service ranges
/// `0x8400_00xx` (SMC32) and `0xC400_00xx` (SMC64). Test-internal `nr`s are tiny, so there is no overlap.
fn is_psci_fid(nr: u64) -> bool {
    let base = nr & 0xFFFF_FF00;
    base == 0x8400_0000 || base == 0xC400_0000
}

/// **M5 Arc 5c — service a PSCI call** the guest made via `HVC`. Supports the calls a single-CPU guest
/// (and Linux) needs: `PSCI_VERSION` (report v1.1), `PSCI_FEATURES` (report `SYSTEM_OFF` implemented),
/// and `SYSTEM_OFF` (the guest powers off — the phase terminal, never returns). Anything else returns
/// `NOT_SUPPORTED`.
fn handle_psci(frame: &mut GuestFrame, uart: &mut Pl011) {
    match frame.x[0] {
        PSCI_VERSION_FID => {
            frame.x[0] = PSCI_VERSION_1_1;
            let _ = writeln!(
                uart,
                "baleen: PSCI_VERSION -> 0x{PSCI_VERSION_1_1:08x} (v1.1)"
            );
        }
        PSCI_FEATURES_FID => {
            // x1 = the queried function ID; SYSTEM_OFF is implemented (0), others not.
            frame.x[0] = if frame.x[1] == PSCI_SYSTEM_OFF_FID {
                0
            } else {
                PSCI_NOT_SUPPORTED
            };
        }
        PSCI_SYSTEM_OFF_FID => {
            PSCI_OFF_OK.store(true, Ordering::Relaxed);
            let _ = writeln!(
                uart,
                "baleen: PSCI SYSTEM_OFF — the guest powered off (serviced by the hypervisor)"
            );
            finish_psci_test(uart); // -> ! (the guest is gone; this is the phase terminal)
        }
        other => {
            frame.x[0] = PSCI_NOT_SUPPORTED;
            let _ = writeln!(
                uart,
                "baleen: PSCI unsupported FID 0x{other:08x} -> NOT_SUPPORTED"
            );
        }
    }
}

/// **M5 Arc 5c** — the guest reported the PSCI version it read (`x1`); assert it equals what the
/// hypervisor returned. A checkpoint.
fn psci_report(frame: &mut GuestFrame, uart: &mut Pl011) {
    let version = frame.x[1];
    let ok = version == PSCI_VERSION_1_1;
    PSCI_VERSION_OK.store(ok, Ordering::Relaxed);
    if ok {
        let _ = writeln!(
            uart,
            "baleen: PSCI version OK: guest read 0x{version:08x} (v1.1) — PSCI is discoverable"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: PSCI version MISMATCH: guest read 0x{version:08x} (expected 0x{PSCI_VERSION_1_1:08x})"
        );
    }
}

/// **M5 Arc 5c, PSCI phase terminal.** Assert the version query + power-off both worked and finish the
/// boot. Reached when the guest calls `SYSTEM_OFF`.
fn finish_psci_test(uart: &mut Pl011) -> ! {
    let version_ok = PSCI_VERSION_OK.load(Ordering::Relaxed);
    let off_ok = PSCI_OFF_OK.load(Ordering::Relaxed);
    if version_ok && off_ok {
        let _ = writeln!(
            uart,
            "baleen: PSCI TEST PASSED — the guest discovered PSCI (v1.1) and powered off via SYSTEM_OFF"
        );
        // M5 Arc 5d: prove the timer TICK — a physical interrupt delivered to the guest. Never returns.
        begin_timer_irq_phase(uart);
    }
    let _ = writeln!(
        uart,
        "baleen: PSCI TEST FAILED (version_ok={version_ok} off_ok={off_ok})"
    );
    crate::park();
}

/// **M5 Arc 5c, PSCI phase.** Build a fresh minimal guest and enter; the guest queries the PSCI version
/// and powers off. Never returns.
fn begin_psci_phase(uart: &mut Pl011) -> ! {
    gic_fresh_guest(uart);
    let entry = load_guest_psci();
    run_gic_guest(
        uart,
        entry,
        "baleen: PSCI phase — a guest queries the PSCI version and powers off via SYSTEM_OFF",
    );
}

/// **M5 Arc 5d** — the guest reported (from its EL1 IRQ vector) the INTID of the timer tick it took
/// (`x1`); assert it is the virtual-timer INTID. A checkpoint.
fn timer_irq_report(frame: &mut GuestFrame, uart: &mut Pl011) {
    let intid = frame.x[1] as u32;
    let ok = intid == gic::VTIMER_INTID;
    TIMER_IRQ_OK.store(ok, Ordering::Relaxed);
    if ok {
        let _ = writeln!(
            uart,
            "baleen: timer tick OK: the guest took an asynchronous virtual-timer interrupt (INTID {intid}) at its EL1 vector"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: timer tick MISMATCH: guest took INTID {intid} (expected {})",
            gic::VTIMER_INTID
        );
    }
}

/// **M5 Arc 5d, timer-tick phase terminal.** Assert the physical tick reached EL2 and the guest took the
/// injected virtual interrupt — the full receive→inject→deliver path — and finish the boot.
fn finish_timer_irq_test(uart: &mut Pl011) -> ! {
    let fired = TIMER_IRQ_FIRED.load(Ordering::Relaxed);
    let taken = TIMER_IRQ_OK.load(Ordering::Relaxed);
    if fired && taken {
        let _ = writeln!(
            uart,
            "baleen: TIMER TICK TEST PASSED — a physical timer interrupt reached EL2 and was delivered to the guest as a virtual interrupt"
        );
        // M5 Arc 6: the finale — assemble the thesis (vault + disposable, non-interference, destroy
        // clean). Never returns (it ends the boot at the thesis terminal).
        begin_thesis_phase(uart);
    }
    let _ = writeln!(
        uart,
        "baleen: TIMER TICK TEST FAILED (fired={fired} taken={taken})"
    );
    crate::park();
}

/// **M5 Arc 5d, timer-tick phase.** Build a fresh minimal guest, initialize the physical GICv3 to receive
/// the virtual-timer PPI at EL2, enable the EL2 physical CPU interface, zero `CNTVOFF_EL2`, and enter. The
/// guest programs its virtual timer with the interrupt un-masked; the tick rides the physical-IRQ → EL2 →
/// inject path to the guest's EL1 vector. Never returns.
fn begin_timer_irq_phase(uart: &mut Pl011) -> ! {
    gic_fresh_guest(uart);
    // Physical side: let EL2 receive PPI 27 (the guest's CNTV) and hand it on as a virtual interrupt.
    gic::init_physical_vtimer();
    gic::enable_physical_cpu_interface_el2();
    // SAFETY: `CNTVOFF_EL2` is an EL2 timer register; writing 0 makes the guest's virtual count track the
    // physical count cleanly (its reset is UNKNOWN). No memory effect.
    unsafe {
        asm!(
            "msr cntvoff_el2, xzr",
            options(nomem, nostack, preserves_flags)
        )
    };
    let entry = load_guest_timer_irq();
    run_gic_guest(
        uart,
        entry,
        "baleen: timer-tick phase — a guest programs its virtual timer and takes the tick as an interrupt",
    );
}

/// First 8 bytes of the vault secret as a little-endian `u64` — what the disposable's probe register
/// (`x2`) would hold if isolation broke and it read the secret.
fn vault_secret_prefix() -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&VAULT_SECRET_MARKER[..8]);
    u64::from_le_bytes(b)
}

/// **M5 Arc 6** — the disposable reported its own-frame read-back (`x1`) and the value its probe of the
/// vault secret read (`x2`, stale iff the probe faulted). Assert its authorized write landed AND it did
/// NOT obtain the secret. If it did (isolation broke), emit the read bytes so the `FORBIDDEN_MARKERS`
/// guard catches the leak. A checkpoint.
fn thesis_pos_report(frame: &mut GuestFrame, uart: &mut Pl011) {
    let readback = frame.x[1];
    let probed = frame.x[2];
    let own_ok = readback == SENTINEL_DISP;
    let secret = vault_secret_prefix();
    if probed == secret {
        // Isolation broke — the disposable read the vault secret. Surface the token so FORBIDDEN fires.
        for &b in &probed.to_le_bytes() {
            uart.put(b);
        }
        let _ = writeln!(
            uart,
            "\nbaleen: THESIS BUG — the disposable read the vault secret"
        );
    }
    let secret_not_read = probed != secret;
    THESIS_POS_OK.store(own_ok && secret_not_read, Ordering::Relaxed);
    if own_ok && secret_not_read {
        let _ = writeln!(
            uart,
            "baleen: thesis: disposable wrote+read its own frame (0x{readback:x}); its probe of the vault secret obtained nothing"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: thesis positive FAILED (own_ok={own_ok} secret_not_read={secret_not_read})"
        );
    }
}

/// Create the disposable + the vault, drive their p2m through the real dispatch, seed the vault's secret
/// and the disposable's CoW disk (M5 Arc 6). The disposable owns a root + data frame; the vault owns a
/// root + a secret frame (distinct `Mfn`s → distinct PA → distinct per-VMID Stage-2 leaf).
fn setup_thesis_model(hv: &mut Hypervisor, uart: &mut Pl011) {
    expect(
        hv,
        DOM0,
        HvCall::DomainCreate {
            target: DISP_DOM,
            may_create: false,
        },
        "create disposable",
        uart,
    );
    expect(
        hv,
        DOM0,
        HvCall::DomainCreate {
            target: VAULT_DOM,
            may_create: false,
        },
        "create vault",
        uart,
    );
    // Disposable: root + data, pin root, link data writable.
    for mfn in [F_DISP_ROOT, F_DISP_DATA] {
        expect(
            hv,
            DISP_DOM,
            HvCall::P2mAllocate { mfn },
            "disp alloc",
            uart,
        );
    }
    expect(
        hv,
        DISP_DOM,
        HvCall::P2mPin {
            mfn: F_DISP_ROOT,
            level: PtLevel::L1,
        },
        "disp pin root",
        uart,
    );
    expect(
        hv,
        DISP_DOM,
        HvCall::P2mLink {
            parent: F_DISP_ROOT,
            slot: 0,
            child: F_DISP_DATA,
            writable: true,
            leaf: true,
        },
        "disp link data",
        uart,
    );
    // Vault: root + secret, pin root, link secret. The vault owns the secret, so it is NOT in the
    // disposable's Stage-2 (owner filter) — the disposable's probe of it faults.
    for mfn in [F_VAULT_ROOT, F_VAULT_SECRET] {
        expect(
            hv,
            VAULT_DOM,
            HvCall::P2mAllocate { mfn },
            "vault alloc",
            uart,
        );
    }
    expect(
        hv,
        VAULT_DOM,
        HvCall::P2mPin {
            mfn: F_VAULT_ROOT,
            level: PtLevel::L1,
        },
        "vault pin root",
        uart,
    );
    expect(
        hv,
        VAULT_DOM,
        HvCall::P2mLink {
            parent: F_VAULT_ROOT,
            slot: 0,
            child: F_VAULT_SECRET,
            writable: true,
            leaf: true,
        },
        "vault link secret",
        uart,
    );
    // Seed the vault's secret HV-side (un-forgeable — the disposable cannot guess or reach it).
    {
        let mut gm = GuestMem;
        if gm
            .write(stage2::frame_ipa(F_VAULT_SECRET), VAULT_SECRET_MARKER)
            .is_err()
        {
            let _ = writeln!(
                uart,
                "baleen: thesis: failed to seed the vault secret; halting"
            );
            crate::park();
        }
    }
    // The disposable's CoW disk: seed the shared template, then write the disposable's overlay so its
    // disk has diverged (the overlay is discarded on teardown, the template staying pristine).
    let disk = blk_disk();
    disk.seed_template(0, THESIS_TEMPLATE_MARKER);
    disk.write(DISP_TENANT, 0, DISP_DISK_MARKER);
}

/// **M5 Arc 6, the thesis phase.** Build a fresh `Hypervisor`, create the disposable + vault, emit the
/// disposable's Stage-2 (which does NOT map the vault's secret), and enter the disposable. It writes its
/// own frame and probes the vault secret → fault. The terminal ([`finish_thesis_test`]) then destroys the
/// disposable and runs the non-interference + lifecycle + channel-enumeration audit. Never returns.
fn begin_thesis_phase(uart: &mut Pl011) -> ! {
    // Reset the per-frame fault records for this incarnation (design-lesson #16).
    for f in 0..NFRAMES {
        FAULT_DFSC[f].store(0, Ordering::Relaxed);
        FAULT_WNR[f].store(false, Ordering::Relaxed);
    }
    // SAFETY: single-CPU, one-time rebuild before the disposable runs.
    unsafe { *GUEST_HV.0.get() = Some(crate::build_hypervisor()) };
    let hv = match unsafe { (*GUEST_HV.0.get()).as_mut() } {
        Some(hv) => hv,
        None => crate::park(),
    };

    setup_thesis_model(hv, uart);

    let vttbr = stage2::build_stage2_from_p2m(hv, DISP_DOM, STAGE2_SET_SINGLE);
    let entry = load_guest_disposable();
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
        "baleen: thesis phase — a control domain runs a disposable alongside a no-net vault holding a secret"
    );
    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    enter_guest(exc_stack_top);
}

/// **M5 Arc 6, thesis terminal — Audit #3, the audit IS the arc.** After the disposable's run, assert the
/// whole thesis: non-interference (the probe faulted + the secret was not read), the channel enumeration
/// (no grant / no shared mapping vault→disposable — the by-construction proof, bridged to the model's
/// Tier-D non-interference theorem), the disposable destroyed clean (Arc 0) with its overlay discarded,
/// and the vault's secret + the CoW template both pristine (Arc 4), plus a reborn disposable that inherits
/// no reach to the secret. Then finish the boot.
fn finish_thesis_test(uart: &mut Pl011) -> ! {
    let hv = match unsafe { (*GUEST_HV.0.get()).as_mut() } {
        Some(hv) => hv,
        None => crate::park(),
    };

    let pos_ok = THESIS_POS_OK.load(Ordering::Relaxed);

    // (1) Non-interference (empirical): the disposable's probe of the vault secret took a translation
    // fault — its Stage-2 has no leaf for the vault's frame.
    let probe_dfsc = FAULT_DFSC[F_VAULT_SECRET as usize].load(Ordering::Relaxed);
    let faulted = is_translation(probe_dfsc);
    if faulted {
        let _ = writeln!(
            uart,
            "baleen: thesis non-interference OK: the disposable's probe of the vault secret -> translation fault (DFSC=0x{probe_dfsc:02x})"
        );
    }

    // (2) Channel enumeration (by construction — the audit IS the arc): NO grant authorizes either
    // direction between vault and disposable, and the vault's secret is owned by the vault (so the
    // disposable's Stage-2 excludes it). Event channels are absent by construction (neither domain issued
    // `EvtchnAllocUnbound`). No authorized channel ⇒ the secret cannot flow — a concrete instance of the
    // model's Tier-D non-interference theorem (see docs/AUDIT-3-NON-INTERFERENCE.md).
    let no_grant = !hv
        .grant()
        .authorizes(VAULT_DOM, DISP_DOM, F_VAULT_SECRET as Frame, false)
        && !hv
            .grant()
            .authorizes(DISP_DOM, VAULT_DOM, F_DISP_DATA as Frame, false);
    let secret_is_vaults = hv.p2m().owner_of(F_VAULT_SECRET) == Some(VAULT_DOM);
    let no_channel = no_grant && secret_is_vaults;
    if no_channel {
        let _ = writeln!(
            uart,
            "baleen: thesis channel enumeration: no grant + no shared mapping vault->disposable (non-interference by construction; bridges to Tier-D)"
        );
    }

    // (3) Destroy the disposable — the proven teardown (Arc 0). Clean shell: Dead + owns no frames.
    let now = {
        use hv_hal::TimeSource;
        crate::time::GenericTimer.now()
    };
    expect(
        hv,
        DOM0,
        HvCall::DomainDestroy {
            target: DISP_DOM,
            now,
        },
        "destroy disposable",
        uart,
    );
    let destroy_clean = !hv.is_live(DISP_DOM)
        && hv.p2m().owner_of(F_DISP_ROOT) != Some(DISP_DOM)
        && hv.p2m().owner_of(F_DISP_DATA) != Some(DISP_DOM);

    // Discard the disposable's disk (its CoW overlay) — a disposable's storage is thrown away on teardown.
    blk_disk().discard_overlay(DISP_TENANT);
    let overlay_gone = !blk_disk().is_dirty(DISP_TENANT, 0);

    // (4) The vault's secret is UNTOUCHED (read it HV-side) and the CoW template is PRISTINE (Arc 4).
    let vault_untouched = read_frame(F_VAULT_SECRET) == vault_secret_prefix();
    let template_pristine =
        &blk_disk().template_sector(0)[..THESIS_TEMPLATE_MARKER.len()] == THESIS_TEMPLATE_MARKER;

    // (5) Reborn inherits nothing (Arc 0): a fresh disposable in the same slot still cannot reach the
    // vault's secret — a `p2m_link` of it is refused `Unauthorized` (not the reborn's frame, no grant).
    expect(
        hv,
        DOM0,
        HvCall::DomainCreate {
            target: DISP_DOM,
            may_create: false,
        },
        "reborn disposable",
        uart,
    );
    expect(
        hv,
        DISP_DOM,
        HvCall::P2mAllocate { mfn: F_DISP_ROOT },
        "reborn alloc root",
        uart,
    );
    expect(
        hv,
        DISP_DOM,
        HvCall::P2mPin {
            mfn: F_DISP_ROOT,
            level: PtLevel::L1,
        },
        "reborn pin root",
        uart,
    );
    let reborn_denied = matches!(
        hv.dispatch(
            DISP_DOM,
            HvCall::P2mLink {
                parent: F_DISP_ROOT,
                slot: 0,
                child: F_VAULT_SECRET,
                writable: true,
                leaf: true,
            },
        ),
        Err(HvError::Unauthorized)
    );
    if reborn_denied {
        let _ = writeln!(
            uart,
            "baleen: thesis reborn OK: a reborn disposable could NOT link the vault's secret (no inherited reach)"
        );
    }

    let ok = pos_ok
        && faulted
        && no_channel
        && destroy_clean
        && overlay_gone
        && vault_untouched
        && template_pristine
        && reborn_denied;
    if ok {
        let _ = writeln!(
            uart,
            "baleen: THESIS TEST PASSED — the vault's secret never reached the disposable; the disposable was destroyed clean (overlay discarded), the vault secret + CoW template pristine (non-interference, bridged to Tier-D)"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: THESIS TEST FAILED (pos_ok={pos_ok} faulted={faulted} no_channel={no_channel} destroy_clean={destroy_clean} overlay_gone={overlay_gone} vault_untouched={vault_untouched} template_pristine={template_pristine} reborn_denied={reborn_denied})"
        );
    }
    selftest_brk(uart);
    crate::park();
}

/// **M5 Arc 5b, virtual-timer phase.** Build a fresh minimal guest, zero `CNTVOFF_EL2` so the guest's
/// virtual count tracks the physical count cleanly, and enter. The guest programs the virtual timer and
/// polls it to expiry. Never returns.
fn begin_timer_phase(uart: &mut Pl011) -> ! {
    gic_fresh_guest(uart);
    // Zero the virtual-count offset so `CNTVCT_EL0` (guest) == the physical count (its reset is UNKNOWN).
    // SAFETY: `CNTVOFF_EL2` is an EL2 timer register; writing 0 has no memory effect.
    unsafe {
        asm!(
            "msr cntvoff_el2, xzr",
            options(nomem, nostack, preserves_flags)
        )
    };
    let entry = load_guest_timer();
    run_gic_guest(
        uart,
        entry,
        "baleen: virtual-timer phase — a guest programs the virtual timer and polls it to expiry",
    );
}

/// Build a fresh `Hypervisor` and create the minimal vGIC guest domain (a pinned page-table root — the
/// guest touches no guest data memory, only its own code + the GIC system registers). Shared by the poll
/// (5a) and async (5b) phases.
fn gic_fresh_guest(uart: &mut Pl011) {
    // SAFETY: single-CPU, one-time rebuild before the vGIC guest runs.
    unsafe { *GUEST_HV.0.get() = Some(crate::build_hypervisor()) };
    let hv = match unsafe { (*GUEST_HV.0.get()).as_mut() } {
        Some(hv) => hv,
        None => crate::park(),
    };
    expect(
        hv,
        DOM0,
        HvCall::DomainCreate {
            target: GIC_DOM,
            may_create: false,
        },
        "create vGIC guest",
        uart,
    );
    expect(
        hv,
        GIC_DOM,
        HvCall::P2mAllocate { mfn: F_GIC_ROOT },
        "vGIC alloc root",
        uart,
    );
    expect(
        hv,
        GIC_DOM,
        HvCall::P2mPin {
            mfn: F_GIC_ROOT,
            level: PtLevel::L1,
        },
        "vGIC pin root",
        uart,
    );
}

/// Emit the vGIC guest's Stage-2, enable the hardware virtual CPU interface at EL2, and enter the guest
/// at `entry`. Shared by the poll (5a) and async (5b) phases. Never returns.
fn run_gic_guest(uart: &mut Pl011, entry: u64, msg: &str) -> ! {
    let hv = match unsafe { (*GUEST_HV.0.get()).as_mut() } {
        Some(hv) => hv,
        None => crate::park(),
    };
    let vttbr = stage2::build_stage2_from_p2m(hv, GIC_DOM, STAGE2_SET_SINGLE);
    let ram_end = core::ptr::addr_of!(__guest_ram_end) as u64;
    enable_stage2(vttbr);
    gic::enable_el2(); // ICC_SRE_EL2 + ICH_HCR_EL2.En + HCR_EL2.IMO — after enable_stage2
    init_guest_el1(ram_end);
    {
        use hv_hal::VcpuOps;
        ArmVcpu.set_entry(entry);
    }
    IN_GUEST_HANDLER.store(false, Ordering::Relaxed);
    let _ = writeln!(uart, "{msg}");
    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    enter_guest(exc_stack_top);
}

/// **M5 Arc 5a, vGIC poll phase.** The guest enables its CPU interface, signals ready (the hypervisor
/// injects a virtual interrupt), and POLLS `ICC_IAR1_EL1` to acknowledge it. Never returns.
fn begin_gic_phase(uart: &mut Pl011) -> ! {
    gic_fresh_guest(uart);
    let entry = load_guest_gic_poll();
    run_gic_guest(
        uart,
        entry,
        "baleen: vGIC phase — a guest enables its GICv3 CPU interface and receives an injected virtual interrupt",
    );
}

/// **M5 Arc 5b, vGIC async-delivery phase.** The guest installs its own EL1 vector table, unmasks IRQs,
/// and TAKES the injected virtual interrupt at its IRQ vector — real vectored delivery. Never returns.
fn begin_gic_async_phase(uart: &mut Pl011) -> ! {
    gic_fresh_guest(uart);
    let entry = load_guest_gic_async();
    run_gic_guest(
        uart,
        entry,
        "baleen: vGIC async phase — a guest takes an injected virtual interrupt at its own EL1 vector table",
    );
}

/// **M5 Arc 4, block phase 6 — the virtio-blk run-loop (tenant 0).** Build a fresh `Hypervisor`, seed
/// the shared template ONCE (it is backend storage that persists across the block phases), create the
/// tenant guest, grant its ring/header/io frames to dom0 (RW ring, RO header, RW io), emit its Stage-2
/// (the mmio window deliberately unmapped), and enter the reader driver. Never returns.
fn begin_virtio_blk_phase6(uart: &mut Pl011) -> ! {
    // Seed the shared read-only template once, before any tenant runs. This is the golden image a clean
    // read falls through to; it is written here and never again (template-immutability).
    blk_disk().seed_template(0, BLK_TEMPLATE_MARKER);
    BLK_TENANT.store(0, Ordering::Relaxed);

    // A fresh Hypervisor: the console phase mutated the previous one. SAFETY: single-CPU, one-time
    // rebuild before the block guest runs; no handler is touching the cell.
    unsafe { *GUEST_HV.0.get() = Some(crate::build_hypervisor()) };
    let hv = match unsafe { (*GUEST_HV.0.get()).as_mut() } {
        Some(hv) => hv,
        None => crate::park(),
    };

    setup_blk_guest(hv, uart);

    let vttbr = stage2::build_stage2_from_p2m(hv, BLK_DOM, STAGE2_SET_SINGLE);
    let entry = load_guest_blk_write();
    let ram_end = core::ptr::addr_of!(__guest_ram_end) as u64;
    enable_stage2(vttbr);
    init_guest_el1(ram_end);
    {
        use hv_hal::VcpuOps;
        ArmVcpu.set_entry(entry);
    }
    IN_GUEST_HANDLER.store(false, Ordering::Relaxed);
    set_active_virtio(ActiveVirtio::Blk); // route trapped mmio to the block register file
    let _ = writeln!(
        uart,
        "baleen: virtio-blk phase (tenant 0) — guest drives a virtio-blk v2 device over a CoW template"
    );
    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    enter_guest(exc_stack_top);
}

/// **M5 Arc 4, block phase 7 — the second tenant (tenant 1).** A fresh `Hypervisor` and a fresh guest,
/// but the **same persisted disk** — the template tenant 0 left pristine, and a distinct overlay. The
/// tenant reads sector 0 and must see the pristine template, not tenant 0's poison: *overlay-isolation*.
/// Never returns.
fn begin_virtio_blk_phase7(uart: &mut Pl011) -> ! {
    // Do NOT re-seed the template: it must survive tenant 0's phase untouched (that survival IS the
    // template-immutability property). Just switch tenant.
    BLK_TENANT.store(1, Ordering::Relaxed);

    // SAFETY: single-CPU, one-time rebuild before the phase-7 guest runs.
    unsafe { *GUEST_HV.0.get() = Some(crate::build_hypervisor()) };
    let hv = match unsafe { (*GUEST_HV.0.get()).as_mut() } {
        Some(hv) => hv,
        None => crate::park(),
    };

    setup_blk_guest(hv, uart);

    let vttbr = stage2::build_stage2_from_p2m(hv, BLK_DOM, STAGE2_SET_SINGLE);
    let entry = load_guest_blk_read();
    let ram_end = core::ptr::addr_of!(__guest_ram_end) as u64;
    enable_stage2(vttbr);
    init_guest_el1(ram_end);
    {
        use hv_hal::VcpuOps;
        ArmVcpu.set_entry(entry);
    }
    IN_GUEST_HANDLER.store(false, Ordering::Relaxed);
    set_active_virtio(ActiveVirtio::Blk);
    let _ = writeln!(
        uart,
        "baleen: virtio-blk phase (tenant 1) — a second tenant reads the shared template (must see it pristine)"
    );
    let exc_stack_top = core::ptr::addr_of!(__exc_stack_top) as u64;
    enter_guest(exc_stack_top);
}

/// **M5 Arc 4 — template-immutability (HV-side), checked after tenant 0's write.** Read the disk's
/// backing storage **directly** (the backend owns it): tenant 0's write must be in its OVERLAY, and the
/// template must be byte-for-byte the seed — a guest write reached the overlay, never the template.
fn check_template_immutability(uart: &mut Pl011) {
    let disk = blk_disk();
    let template_pristine =
        &disk.template_sector(0)[..BLK_TEMPLATE_MARKER.len()] == BLK_TEMPLATE_MARKER;
    let overlay_has_write =
        &disk.overlay_sector(0, 0)[..BLK_POISON_MARKER.len()] == BLK_POISON_MARKER;
    if template_pristine && overlay_has_write {
        BLK_WRITE_ISOLATED_OK.store(true, Ordering::Relaxed);
        let _ = writeln!(
            uart,
            "baleen: virtio-blk template-immutability OK: tenant 0's write landed in its CoW overlay; the template is pristine"
        );
    } else {
        let _ = writeln!(
            uart,
            "baleen: virtio-blk template-immutability FAILED (template_pristine={template_pristine} overlay_has_write={overlay_has_write})"
        );
    }
}

/// Create the block tenant guest and its granted frames in `hv` (shared by both tenant phases). The guest
/// owns a page-table root + the virtqueue, header, and I/O frames it links writable and grants to dom0:
/// the ring RW (the backend writes the used ring), the header RO (device-readable), the I/O frame RW (the
/// backend writes the read data + status). `F_BLK_UNGRANTED` is allocated + linked but deliberately NOT
/// granted — a later step points a descriptor at it as the grant negative.
fn setup_blk_guest(hv: &mut Hypervisor, uart: &mut Pl011) {
    expect(
        hv,
        DOM0,
        HvCall::DomainCreate {
            target: BLK_DOM,
            may_create: false,
        },
        "create blk guest",
        uart,
    );
    for mfn in [F_BLK_ROOT, F_BLK_VQ, F_BLK_HDR, F_BLK_IO, F_BLK_UNGRANTED] {
        expect(
            hv,
            BLK_DOM,
            HvCall::P2mAllocate { mfn },
            "blk alloc frame",
            uart,
        );
    }
    expect(
        hv,
        BLK_DOM,
        HvCall::P2mPin {
            mfn: F_BLK_ROOT,
            level: PtLevel::L1,
        },
        "blk pin root",
        uart,
    );
    for (slot, child) in [
        (0u32, F_BLK_VQ),
        (1u32, F_BLK_HDR),
        (2u32, F_BLK_IO),
        (3u32, F_BLK_UNGRANTED),
    ] {
        expect(
            hv,
            BLK_DOM,
            HvCall::P2mLink {
                parent: F_BLK_ROOT,
                slot,
                child,
                writable: true,
                leaf: true,
            },
            "blk link frame",
            uart,
        );
    }
    // Grant the ring (RW), header (RO — device only reads it), and I/O frame (RW — device writes read
    // data + status). `F_BLK_UNGRANTED` is intentionally left un-granted.
    for (gref, frame, readonly) in [
        (0u32, F_BLK_VQ, false),
        (1u32, F_BLK_HDR, true),
        (2u32, F_BLK_IO, false),
    ] {
        expect(
            hv,
            BLK_DOM,
            HvCall::GrantAccess {
                gref: gref as GrantRef,
                grantee: BLK_BACKEND,
                frame: frame as Frame,
                readonly,
            },
            "blk grant frame",
            uart,
        );
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
