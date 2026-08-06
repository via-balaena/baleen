// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! # `EC=0x24` data-abort syndrome decode — **one** derivation, two trap handlers
//!
//! A Stage-2 data abort is the metal's trap-and-emulate transport: the device window is left
//! unmapped, a guest load/store to a device register faults to EL2, and the handler reads what the
//! access *was* out of `ESR_EL2.ISS` (which register, which direction, how wide) and where it was
//! aimed (`HPFAR_EL2` + `FAR_EL2`). Two handlers now need that: the synthetic guest's virtio-mmio
//! path ([`crate::guest`], M5 Arc 3) and the real-Linux guest's emulated PL011 (`crate::vpl011`,
//! ③-a1).
//!
//! **This module exists so there is one decode, not two.** ⑭ found `VTCR_EL2` written out as a
//! literal in `linux.rs` while `guest.rs` derived it — two encodings of one architectural fact that
//! agreed by coincidence. An `ISS` field decode written twice is the same shape, and the failure is
//! worse than a mismatched register: the two handlers would disagree about *which guest register a
//! load lands in*. So the bit positions live here, are `pub(crate)`, and both handlers read them.
//!
//! ## Provenance
//!
//! `ESR_ELx.ISS` for Data Abort (`EC = 0b100100`, lower EL) and `HPFAR_EL2.FIPA` are from the **Arm
//! Architecture Reference Manual for A-profile** (D17 "AArch64 System Register Descriptions") — a
//! published specification, the `CLEANROOM.md` hygiene applied to standard hardware.
//!
//! ## Unsafe
//!
//! **None.** This module is pure bit arithmetic over values the callers read out of system
//! registers; the `mrs` reads themselves stay in the handlers that own them.

/// The exception class of a lower-EL **data abort**, `ESR_ELx.EC[31:26]`. The value both sync
/// handlers branch on.
pub(crate) const EC_DATA_ABORT: u64 = 0x24;

/// A decoded `ESR_EL2.ISS` for a data abort — everything an emulator needs to service the access.
///
/// Fields are named as the Arm ARM names them, so the decode below can be read against the manual.
///
/// **Two of them are `cfg`-gated, deliberately, and this is not a lint dodge.** `sf` and `s1ptw`
/// mean something only to a guest that runs with its **stage-1 MMU on** and at more than one access
/// width — i.e. the real Linux guest. The synthetic guests run stage-1 off and their virtio-mmio
/// register file is word-only, so in the default build those two fields would be decoded and never
/// read. ⑭'s lesson is that the answer to "this is unused in that configuration" is **not** an
/// `allow(dead_code)`, which would then absorb the next genuinely-dead field silently; it is to say
/// which configuration the item belongs to, and let every configuration lint what it compiles.
#[derive(Clone, Copy)]
pub(crate) struct DataAbort {
    /// `ISV` — the instruction syndrome is valid, i.e. `SAS`/`SRT`/`SF`/`WnR` below mean anything.
    /// Clear for accesses the CPU cannot describe (load/store-multiple, `DC ZVA`, some S1PTW
    /// faults); an emulator must refuse those rather than guess.
    pub(crate) isv: bool,
    /// `SAS` — access size, `0..=3` for byte/half/word/doubleword. See [`Self::access_bytes`].
    pub(crate) sas: u64,
    /// `SRT` — the GP register number the access loads into or stores from (`31` = `XZR`).
    pub(crate) srt: usize,
    /// `SF` — the transfer register is 64-bit (else 32-bit, so a load zero-extends).
    #[cfg(feature = "real-linux")]
    pub(crate) sf: bool,
    /// `WnR` — the access was a **write**.
    pub(crate) wnr: bool,
    /// `FnV` — `FAR_EL2` is **not** valid. When set, the in-page offset cannot be recovered and no
    /// register-level emulation is possible.
    pub(crate) fnv: bool,
    /// `S1PTW` — the fault was taken on a **stage-1 translation-table walk**, so the address is a
    /// guest page-table address rather than the address the instruction named. Unreachable for a
    /// guest with stage-1 off, hence the gate.
    #[cfg(feature = "real-linux")]
    pub(crate) s1ptw: bool,
}

impl DataAbort {
    /// Decode `ESR_EL2` for a data abort. The caller has already established `EC == 0x24`.
    pub(crate) fn decode(esr: u64) -> Self {
        let iss = esr & 0x01ff_ffff; // ESR_ELx.ISS[24:0]
        Self {
            isv: (iss >> 24) & 1 != 0,
            sas: (iss >> 22) & 0b11,
            srt: ((iss >> 16) & 0x1f) as usize,
            #[cfg(feature = "real-linux")]
            sf: (iss >> 15) & 1 != 0,
            wnr: (iss >> 6) & 1 != 0,
            fnv: (iss >> 10) & 1 != 0,
            #[cfg(feature = "real-linux")]
            s1ptw: (iss >> 7) & 1 != 0,
        }
    }

    /// Bytes transferred by the access: `1 << SAS`, i.e. 1, 2, 4 or 8.
    pub(crate) fn access_bytes(&self) -> u64 {
        1 << self.sas
    }

    /// The mask of the bits the access actually carries (`0xff`, `0xffff`, `0xffff_ffff`, all ones).
    pub(crate) fn value_mask(&self) -> u64 {
        match self.sas {
            0 => 0xff,
            1 => 0xffff,
            2 => 0xffff_ffff,
            _ => u64::MAX,
        }
    }
}

/// The **page-aligned** faulting IPA, from `HPFAR_EL2`.
///
/// `HPFAR_EL2.FIPA` is bits `[43:4]` holding `IPA[47:12]`, so the address is
/// `(HPFAR_EL2 & mask) << 8` (bit 4 → bit 12). This is the architectural IPA source for a Stage-2
/// fault; `FAR_EL2` carries the guest **VA**, which is only equal to the IPA when the guest runs
/// with stage-1 off.
pub(crate) fn page_ipa(hpfar: u64) -> u64 {
    (hpfar & 0x0000_0fff_ffff_fff0) << 8
}

/// The **full** faulting IPA, including the in-page offset — what register-level MMIO emulation
/// needs (which device register was touched).
///
/// `HPFAR_EL2` supplies `IPA[47:12]`; the low 12 bits are not in it. They come from `FAR_EL2`,
/// whose low 12 bits are the same as the IPA's because a 4 KiB translation granule leaves
/// `addr[11:0]` untouched — so this is correct whether the guest's stage-1 MMU is **on** (the real
/// Linux guest, once it has enabled paging) or **off** (the synthetic guests, where `FAR_EL2` is
/// the whole address on its own).
///
/// Only meaningful when [`DataAbort::fnv`] is clear — with `FnV` set the caller must refuse.
///
/// Gated for the same reason as [`DataAbort::sf`]: the synthetic guests run stage-1 off, so their
/// handler takes the whole address from `FAR_EL2` and needs only [`page_ipa`].
#[cfg(feature = "real-linux")]
pub(crate) fn full_ipa(hpfar: u64, far: u64) -> u64 {
    page_ipa(hpfar) | (far & 0xfff)
}
