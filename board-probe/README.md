<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `board-probe` — what does this board actually do?

A standalone bare-metal AArch64 instrument that **measures the platform facts `hv-metal` currently
assumes from QEMU `virt`**. Run it on a candidate board *before* porting anything.

It is **not** part of the hypervisor, **not** gated by CI beyond its own health
(`cargo xtask fvp-lint` builds it), and shares **no source** with `hv-metal` — the same fence
`fvp-probe` keeps, for the same reason: an instrument that imports the declarations of the thing it
measures is a tautology, not evidence.

## Why it exists before the port

`hv-metal` has never run outside QEMU `virt`, and it holds **every platform fact as a `const`** — it
parses no device tree for itself. Porting means replacing those constants, and each replacement is a
decision resting on a number nobody has measured on the target.

That is design-lesson **#248**: *build the instrument before the code when nothing you run can grade
the code.* `fvp-probe` did exactly this for ledger 5's A2 and found a requirement the spec did not
have — the SMMU command bytes needing publication, which fails **silently** when omitted.

★ **So this probe answers questions; it ports nothing.** A `DIFFERS` is not a failure. It is the
finding, and it is what the port's scope should be built from.

## Running it

```
board-probe/qemu-probe.sh          # the self-test — run this FIRST, every time
```

⚠ **The self-test is not a formality.** The probe's output is only worth something if the instrument
is known to work, and the only way to know that is to run it where the answers are already
established. Every verdict must read `MATCH` or `SUPPORTS` on QEMU `virt`; anything else indicts the
**probe**, not the platform.

★ **On its first run it found four bugs in itself** — three of them one conceptual error (comparing
for *equality* what is a *capability*: `hv-metal` **chooses** 40-bit PAs, 4 KiB granules and 8-bit
VMIDs, and a platform offering 52 / 52-bit-capable / 16 has **headroom**, not a mismatch), and one a
checker whose pattern matched its own explanatory prose. That is #211 working: build the control so
it can falsify itself.

## The two facts you must supply

Everything else is read from the hardware. These two are chicken-and-egg and come from the board's
own documentation:

| fact | where | symptom if wrong |
|---|---|---|
| **load address** | `link.ld` | silent hang — the image never runs |
| **UART base** | `src/main.rs`'s `UART0_BASE` | silent hang — nothing to report *on* |

⚠ And a third thing that is not an address: `uart_init`/`putc` are **PL011-specific**. A board with
an 8250/16550 or vendor UART needs its own two functions, not a different base.

## What it measures, and what depends on each

| fact | what in `hv-metal` depends on it |
|---|---|
| `CurrentEL` | **everything** — an EL1 hand-off means the board cannot host baleen as configured |
| `SCTLR_EL2` **at reset** | QEMU reports a flat `0x0`; silicon should read RES1 bits back as 1. `mmu.rs` does a read-modify-write **for exactly this** and has never met a non-zero value |
| `CTR_EL0.DminLine` | `cache.rs`'s maintenance stride (#169 — a stride *wider* than the true line skips lines) |
| `ID_AA64MMFR0.PARange` | `mmu.rs` pins `TCR_EL2.PS = 0b010` (40-bit) |
| `ID_AA64MMFR0.TGran4` | `hv-metal` emits **only** the 4 KiB granule |
| `ID_AA64MMFR1.VMIDBits` | `stage2.rs` uses 8-bit VMIDs (`VTCR_EL2.VS = 0`) |
| `ICH_VTR_EL2` | the vGIC list-register bank and priority bits — the context layout follows |
| `CNTFRQ_EL0` | the scheduler slice length (`time.rs` documents it as advisory) |
| `x0` at entry | the DTB pointer, if the boot chain passes one |

⚠⚠ **It must not fault at EL1.** Reading `SCTLR_EL2` or `ICH_VTR_EL2` from EL1 traps, and a probe
that dies before printing is worse than no probe — you cannot distinguish "the board is EL1-only"
from "the image never ran". `CurrentEL` is read first, on the only path needing no privilege, and
every EL2 register is gated behind it.

## Measured: QEMU `virt`, `-cpu max`, virtualization=on

The baseline. Every future board transcript should be read as a **diff against this**.

```text
@@ BOARD-PROBE-BEGIN
@@ note: raw facts are `@@ key = value`; comparisons against hv-metal are `@@ VERDICT`.
@@ CurrentEL = EL2
@@ VERDICT el2: MATCH  — entered at EL2, as hv-metal requires
@@ MIDR_EL1 = 0x00000000000f0510
@@ MPIDR_EL1 = 0x0000000080000000
@@ x0_at_entry = 0x0000000000000000
@@ note: x0 is conventionally a DTB pointer; 0 means the boot chain passed none.
@@ CTR_EL0 = 0x00000000b444c004
@@ CTR_EL0.IminLine bytes = 64
@@ VERDICT dcache_line: MATCH  — hv-metal assumes 64 bytes, measured 64
@@ ID_AA64MMFR0_EL1 = 0x2100032310201126
@@ VERDICT pa_range: SUPPORTS — hv-metal needs 40 bits, platform offers 52
@@ VERDICT granule_4k: SUPPORTS — hv-metal emits only 4 KiB (TGran4 = 0x1)
@@ ID_AA64MMFR1_EL1 = 0x0110112010312122
@@ VERDICT vmid_bits: SUPPORTS — hv-metal needs 8 bits, platform offers 16
@@ ICH_VTR_EL2 = 0x0000000090b80003
@@ VERDICT list_registers: MATCH  — hv-metal assumes 4 LRs, measured 4
@@ VERDICT priority_bits: MATCH  — hv-metal assumes 5 bits, measured 5
@@ SCTLR_EL2_at_reset = 0x0000000000000000
@@ VERDICT sctlr_res1: MATCH  — QEMU reports a flat 0x0; silicon should read RES1 bits back as 1
@@ note: a non-zero value here is EXPECTED and is good news — it is the case mmu.rs's
@@ note: read-modify-write of SCTLR_EL2 was written for and has never met.
@@ CNTFRQ_EL0 = 0x000000003b9aca00
@@ note: CNTFRQ_EL0 is firmware-programmed and documented as advisory; a wrong value gives
@@ note: a slice of the wrong duration, not a lost guarantee.
@@ BOARD-PROBE-END
```

## ⛔ What this can never be

**A CI gate.** A board on a desk is not reproducible, which is the same reasoning that declined a
full FVP port: a required gate must be reproducible, and the standard this project already holds is
the real-Linux gate building from checksum-pinned URLs. Board results are **local evidence**, exactly
like `fvp-probe`'s milestone verdicts — and every strong claim this project makes about silicon
behaviour already has that standing.
