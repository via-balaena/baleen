// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! A **small bare-metal monitor partition, running beside a real Linux partition.**
//!
//! ## Why this exists
//!
//! `docs/CONSUMER-CORTENFORGE.md` derives a mixed-criticality deployment: an untrusted learned
//! control policy in one partition, a safety monitor in another. Every other requirement in that
//! document's table is either already built or gated on a physical board. **This one was gated on
//! nothing** — and it was the requirement that makes the architecture real rather than notional,
//! because a monitor running full Linux has a TCB nobody can certify under IEC 61508 / ISO 13482.
//! The whole runtime-assurance argument rests on the monitor being small and analyzable.
//!
//! ⚠ **Both halves were already built, and nothing had ever run them together.** `hv-metal` boots
//! either `crate::linux::NUM_GUESTS` unmodified kernels **or** the synthetic bare-metal phases —
//! `main.rs`'s `#[cfg]` makes them mutually exclusive, and the module doc there says the synthetic
//! phases are *"replaced by"* the real-Linux capstone. So the configuration the consumer needs was
//! the one configuration the metal could not express.
//!
//! ## What this module is, and what it deliberately is not
//!
//! It is a **payload**: a few dozen instructions in `.rodata.guest`, copied into a guest slot's own
//! RAM window and entered by the same context restore that starts every non-boot guest. It is
//! emphatically **not** `crate::guest`'s synthetic phase machinery running beside `crate::linux` —
//! that machinery drives a whole boot (it builds its own `Hypervisor`, runs a lifecycle, and parks),
//! and composing two such drivers is what "both paths assume they own the machine" actually means.
//! The monitor is a *tenant*, not a second driver.
//!
//! ★ **The rung is therefore much smaller than it first looks, and the reason is worth stating
//! because it generalizes: `crate::linux::run` `eret`s into slot A only.** Every other slot is
//! entered by [`crate::vcpu::VcpuCtx::seed_boot`] + a context restore, and nothing on that path is
//! Linux-specific except the *values* it is handed (`kernel_entry`, `dtb_addr`, `SPSR_EL2_LINUX`).
//! A bare-metal tenant is a different argument set and a different payload — not a new boot path,
//! and so not a second copy of the entry sequence to keep in step (design-lesson #130).
//!
//! ## What the payload does, and why each part is evidence rather than decoration
//!
//! 1. **It announces itself through its own emulated PL011.** A write to [`crate::vpl011::VPL011_BASE`]
//!    is an unmapped Stage-2 address: it aborts to EL2, is decoded, and is serviced by *this slot's*
//!    `DeployedPl011`. `crate::console` then tags the line with the domain that received the byte.
//!    So a `[dom N] baleen-monitor: …` line on the transcript is produced by the per-guest device
//!    model having actually run for a **second, non-Linux tenant** — the witness is made by the
//!    mechanism that would have to be working for the claim to be true (design-lesson #24(f)).
//!
//! 2. **It yields with `wfi`, and takes the CPU back.** `HCR_WITH_TWI` traps guest `WFI`, so the
//!    monitor hands its remaining slice to the peer rather than burning it. Each round therefore
//!    costs a real round trip through `hv-core`'s scheduler and back. ★ **This is the co-residency
//!    evidence, and it is why the payload loops instead of printing once**: a single line proves a
//!    payload was entered, whereas [`ROUNDS`] interleaved lines prove the two partitions were
//!    *repeatedly* scheduled against each other on one pCPU.
//!
//! 3. **It retires through PSCI `SYSTEM_OFF`**, exactly as a Linux guest does. Not a courtesy: the
//!    boot ends when *every* slot has powered off (`crate::linux`'s final report), so a monitor that
//!    looped forever would hang the gate. Retiring through the same FID means it retires through the
//!    same code, so there is no second shutdown path that runs once and is never exercised again.
//!
//! ## ⚠ What this rung does NOT claim, stated here because the name invites the overclaim
//!
//! **It observes nothing.** A monitor that watches no one is a partition, not a monitor, and calling
//! it one in the transcript would be exactly the class of defect this project keeps finding. The
//! observation channel — a read-only view of the policy partition's memory, authorized by a grant and
//! realized by the proven emitter — is the **next** rung, and it is the one that has to weaken
//! `crate::linux`'s disjointness claim to say something true. What is closed here is *co-residency*:
//! a small analyzable partition and an unmodified Linux kernel, isolated, time-slicing one pCPU.
//!
//! ⚠ **The payload is not a certifiable monitor either**, and no part of the transcript should be
//! read as saying so. It is the smallest tenant that demonstrates the configuration; what a real
//! monitor computes is the consumer's, and it is out of this repository's scope.

use core::arch::global_asm;
use core::fmt::Write;

use crate::pl011::Pl011;

/// How many observe-and-yield rounds the payload runs before retiring.
///
/// **Four, and the number is a lower bound on evidence rather than a taste.** One round shows the
/// payload was entered; what the rung claims is that two partitions were *repeatedly* scheduled
/// against each other, which needs the monitor to leave the pCPU and come back. Four rounds means
/// three demonstrated returns, with margin over the one-return minimum so the witness does not sit
/// on the threshold it is testing.
///
/// ⚠ **Kept to a single decimal digit on purpose** — the payload prints the round number with an
/// `add w0, w20, #0x30`, which is a one-instruction conversion only while the count stays under ten.
/// Raising this past 9 silently prints punctuation instead of a digit, so the bound is asserted
/// rather than left as a comment.
pub(crate) const ROUNDS: u64 = 4;

const _: () = assert!(
    ROUNDS < 10,
    "the payload converts the round number with a single-digit `add #0x30`; a larger count would \
     print punctuation. Widen the conversion in the template before raising this."
);

/// The high half of [`crate::vpl011::VPL011_BASE`], for the payload's `movz … lsl #16`.
///
/// Derived rather than written: a second literal for the console address is a second thing to drift,
/// and the payload cannot be type-checked against the emulator it talks to.
const VPL011_HI: u64 = crate::vpl011::VPL011_BASE >> 16;

const _: () = assert!(
    VPL011_HI << 16 == crate::vpl011::VPL011_BASE,
    "the emulated PL011 base is no longer expressible as a single `movz … lsl #16`; the payload's \
     console address would be wrong"
);

/// The two halves of PSCI `SYSTEM_OFF`, for the payload's `movz`/`movk` pair.
///
/// Same derivation argument as [`VPL011_HI`]: `crate::linux` owns the FID, and the payload must
/// retire through the *same* one a Linux guest issues or it would exercise a different path.
const PSCI_OFF_HI: u64 = crate::linux::PSCI_SYSTEM_OFF_FID >> 16;
/// The low half of the PSCI `SYSTEM_OFF` FID.
const PSCI_OFF_LO: u64 = crate::linux::PSCI_SYSTEM_OFF_FID & 0xffff;

const _: () = assert!(
    (PSCI_OFF_HI << 16) | PSCI_OFF_LO == crate::linux::PSCI_SYSTEM_OFF_FID,
    "the PSCI SYSTEM_OFF FID no longer splits into the movz/movk pair the payload builds"
);

// ---------------------------------------------------------------------------------------------
// The monitor payload.
//
// Position-independent by construction — every branch is PC-relative and every string is reached by
// `adr` — because the blob is *linked* inside hv-metal's `.rodata` and *executed* from a guest RAM
// window megabytes away. That is the same property `crate::guest`'s templates rely on, and for the
// same reason; it is a property of how it is written, so it is stated here rather than checked.
//
// Register discipline, fixed for the whole blob:
//   x19 — the emulated PL011's `DR`, loaded once
//   x20 — the round counter
//   x0/x1 — arguments and scratch for `puts`
//   x30 — the link register, clobbered by every `bl`. Named because it is the one register the
//         code touches without mentioning: `puts` is never called from inside `puts`, so a single
//         level is all that is needed and no stack is used anywhere in the payload. **The payload
//         therefore writes NO memory at all** — which is what keeps `first_word`'s readback of the
//         deposited bytes a valid witness for the whole boot, including after the monitor has run.
// ---------------------------------------------------------------------------------------------
global_asm!(
    r#"
    .section .rodata.guest, "a"
    .balign 4
    .global __monitor_tpl_start
__monitor_tpl_start:
    movz    x19, #{VPL011_HI}, lsl #16      // x19 = the emulated PL011's DR, for the whole blob
    adr     x0, 30f
    bl      20f                             // announce the partition
    mov     x20, #0

    // ── one observation round: yield the slice, come back, say so ──
10: wfi                                     // traps (HCR_EL2.TWI); EL2 hands the pCPU to the peer
    add     x20, x20, #1
    adr     x0, 31f
    bl      20f
    add     w0, w20, #0x30                  // the round number, single-digit by `ROUNDS`'s assert
    str     w0, [x19]
    mov     w0, #0x0a                       // '\n' — `console` emits on the newline
    str     w0, [x19]
    cmp     x20, #{ROUNDS}
    b.lt    10b

    adr     x0, 32f
    bl      20f
    movz    x0, #{PSCI_OFF_HI}, lsl #16     // retire exactly as a Linux guest does
    movk    x0, #{PSCI_OFF_LO}
    hvc     #0
11: wfe                                     // unreachable: SYSTEM_OFF does not return
    b       11b

    // ── puts(x0): a NUL-terminated string, byte at a time through DR ──
20: ldrb    w1, [x0], #1
    cbz     w1, 21f
    str     w1, [x19]
    b       20b
21: ret

30: .asciz "baleen-monitor: alive — a bare-metal EL1 partition beside an unmodified Linux guest\n"
31: .asciz "baleen-monitor: round "
32: .asciz "baleen-monitor: rounds complete, retiring through PSCI SYSTEM_OFF\n"
    .balign 4
    .global __monitor_tpl_end
__monitor_tpl_end:
    "#,
    VPL011_HI = const VPL011_HI,
    ROUNDS = const ROUNDS,
    PSCI_OFF_HI = const PSCI_OFF_HI,
    PSCI_OFF_LO = const PSCI_OFF_LO,
);

extern "C" {
    /// First byte of the monitor payload, in `hv-metal`'s own `.rodata`.
    static __monitor_tpl_start: u8;
    /// One past the last byte of the monitor payload.
    static __monitor_tpl_end: u8;
}

/// **The payload's first instruction word**, read from `hv-metal`'s own `.rodata`.
///
/// The monitor's analogue of Linux's `ARM\x64` header magic, and used for the same job: witnessing
/// that a guest's window really holds *its* payload. ★ **Read from the template rather than pinned
/// as a constant**, which makes it strictly better evidence than a magic number — it compares the
/// deposited bytes against the very bytes that were deposited, so it cannot be satisfied by a
/// coincidence and needs no updating when the payload changes.
pub(crate) fn first_word() -> u32 {
    // SAFETY: `__monitor_tpl_start` is this image's own `.rodata`, 4-byte aligned by the `.balign 4`
    // in the template, and the payload is non-empty (checked in `load`, which halts otherwise).
    unsafe { core::ptr::read_volatile(core::ptr::addr_of!(__monitor_tpl_start) as *const u32) }
}

/// **Copy the monitor payload into guest slot `slot`'s RAM window**, and report what was deposited.
///
/// Called in place of the `-device loader` deposit a Linux slot gets: the monitor needs no external
/// artifact, so its "loader" is this copy.
///
/// ⚠ **Returns nothing, deliberately.** An earlier draft returned "the entry address" — which is
/// the window base — and no caller used it, because `crate::linux` already derives a slot's entry
/// from `kernel_entry(slot)` and seeds the context with that. Handing back a second answer to
/// "where does this payload start" would be two derivations of one fact, agreeing today and free to
/// drift; the entry point is the window base for both payloads because the arm64 boot protocol's
/// "entry at the base of RAM" is a property of the WINDOW, not of Linux.
///
/// ⚠ **Reports the byte count rather than asserting one.** The payload's size is whatever the
/// assembler produced; pinning it would be a number nothing measures against a second reading
/// (design-lesson #251), and it would have to be bumped on every wording change to a string. What
/// IS checked is that the blob is non-empty and fits, both of which are real failures — an empty
/// template would `eret` into whatever the window last held.
pub(crate) fn load(uart: &mut Pl011, slot: usize, window_base: u64, window_len: u64) {
    let start = core::ptr::addr_of!(__monitor_tpl_start) as usize;
    let end = core::ptr::addr_of!(__monitor_tpl_end) as usize;
    let len = end - start;

    if len == 0 || len as u64 > window_len {
        let _ = writeln!(
            uart,
            "baleen: monitor FAIL: the payload is {len} bytes, which does not fit a {window_len}-byte \
             window (or is empty — an empty payload would enter whatever the window last held); halting"
        );
        crate::park();
    }

    // SAFETY: the source is this image's own `.rodata.guest` blob, delimited by the two linker
    // symbols above; the destination is the base of guest slot `slot`'s RAM window, which the
    // partition assigns to this slot alone and which the bounds check above proves is larger than
    // the payload. The two regions are distinct — `.rodata` is inside hv-metal's image, below
    // `LINUX_RAM_BASE`. Nothing is executing from the destination: this runs before any `eret`.
    unsafe {
        core::ptr::copy_nonoverlapping(start as *const u8, window_base as *mut u8, len);
    }

    let _ = writeln!(
        uart,
        "baleen: monitor OK: dom {} carries the bare-metal monitor payload — {len} bytes copied to \
         0x{window_base:08x} from EL2's own .rodata, no external image and no device tree; it runs \
         {ROUNDS} observe-and-yield rounds against its peer and then powers off",
        crate::linux::slot_dom(slot)
    );
}
