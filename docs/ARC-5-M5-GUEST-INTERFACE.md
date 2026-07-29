<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# M5 Arc 5 — the guest hardware interface: interrupts, timer, PSCI

Arc 5 gives a guest the three things it needs from a hypervisor beyond memory and virtio: **interrupts**,
a **timer**, and **PSCI** (power). This is the plumbing that a real Linux guest will use at the capstone;
it is built and proven here with synthetic guests that drive the **real** hardware interfaces, so a Linux
kernel uses them unchanged. **No new isolation content** — the isolation thesis is already proven on the
Arc 0–4 synthetic guests; Arc 5 adds capabilities, audited only for whether they open a new cross-domain
channel (Audit #7: they do not). `hv-core`/`hv-hal` are untouched (this refines).

## The approach — hardware GIC virtualization, not software emulation

The QEMU `virt` machine (with `gic-version=3`) exposes the ARM **GIC virtualization extensions** at EL2 —
the `ICH_*` list registers. Rather than emulate a GICv3 in software, the hypervisor makes a virtual
interrupt *pending* for the guest by writing a list register (`ICH_LR0_EL2`) and lets the hardware CPU
interface deliver it — exactly how KVM and Xen do it. `hv-metal/src/gic.rs` holds the vGIC.

## The sub-arcs (each boot-tested, CI-green)

- **5a — vGIC injection.** Enable the virtual CPU interface at EL2 (`ICC_SRE_EL2`, `ICH_HCR_EL2.En`,
  `HCR_EL2.IMO`); a synthetic guest enables its GICv3 CPU interface (`ICC_SRE_EL1`/`PMR`/`IGRPEN1`) and
  acknowledges an injected virtual interrupt via `ICC_IAR1_EL1`. (Surfaced + fixed: the machine defaulted
  to GICv2 — no GICv3 CPU-interface system registers — so `gic-version=3` was added to the machine args.)
- **5b — async vectored delivery + the virtual timer.** (1) A guest installs its **own EL1 vector table**
  (`VBAR_EL1`, via a 0x800-aligned blob so the table lands aligned), unmasks IRQs (`DAIFClr`), and *takes*
  the injected interrupt at its IRQ vector — real vectored delivery. (2) A guest uses the architected
  **virtual timer** (`CNTV`) for timekeeping: program `CNTV_TVAL`, poll `CNTV_CTL.ISTATUS` to expiry.
- **5c — PSCI.** The HVC handler recognizes PSCI function IDs (SMC convention) and services `PSCI_VERSION`
  (v1.1), `PSCI_FEATURES`, and `SYSTEM_OFF` (the guest powers off). A guest queries the version and powers
  off — exactly how Linux uses PSCI with `method = "hvc"`.
- **5d — the timer TICK (the EL2-IRQ keystone).** The full physical-interrupt delivery path. A guest
  programs its virtual timer with the interrupt un-masked; the timer fires the physical PPI 27, routed to
  EL2 by `HCR_EL2.IMO`; a **new EL2 IRQ handler** (vector slot 9 → `__guest_irq_entry` → `handle_guest_irq`)
  acknowledges the physical interrupt, disables the level-triggered timer so it does not re-fire, and
  injects the matching **virtual** interrupt; the guest takes it asynchronously at its EL1 vector. This
  required real physical GICv3 init (distributor + this CPU's redistributor wake + enable PPI 27) and the
  EL2 physical CPU interface. This receive→inject path is what virtio used-buffer interrupts reuse.

## 5e — the real Linux capstone (DONE)

The capstone is landed (`hv-metal/src/linux.rs`, feature `real-linux`; run via `cargo xtask qemu-linux`).
A **real Alpine Linux 6.18 aarch64 kernel** boots end-to-end as a single EL1 guest that owns the machine,
reaches userspace (runs `/init`), and powers off via PSCI `SYSTEM_OFF` — serviced by hv-metal's HVC
handler — exactly as the interface above predicted. Everything built for the synthetic guests carries an
unmodified kernel unchanged:

- **Large guest-RAM Stage-2 map + device pass-through.** A big identity Stage-2 maps guest RAM
  (`0x4800_0000..0x8000_0000`, Normal WB) plus the GICv3 + PL011 device pages, with `HCR_EL2.IMO=0`
  so the kernel drives the real GIC / arch-timer / PL011 directly (the vGIC injection path is the
  *multi-guest* mechanism, unused here). hv-metal owns the low 128 MiB; the guest never maps it.
  (**Superseded in part by §5g:** the PL011 is no longer passed through — it is emulated in EL2, so
  the window is 16 MiB and covers the GIC alone. The GIC and `IMO=0` are unchanged.)
- **DTB.** A minimal device tree (`hv-metal/linux/guest.dts`) — only the nodes the guest drives (psci
  `method="hvc"`, memory, GICv3, PL011, timer, cpu, chosen), so Linux probes only what the
  hypervisor presents. `x0` = the DTB per the arm64 boot protocol; the kernel `Image` + initramfs are
  placed in guest RAM by QEMU `-device loader`.
  (**Superseded in part by §5g:** "presents" is no longer a synonym for "passes through". The PL011
  node is still in the DTB and `earlycon=pl011` still works, but that device is now **emulated in
  EL2** rather than mapped — the DTB is byte-for-byte unchanged across that shift, which is the
  point. Everything else in the list is still pass-through.)
- **PSCI over HVC.** `PSCI_VERSION` / `FEATURES` / `SYSTEM_OFF` serviced; unknown FIDs (e.g. the
  kernel's `MIGRATE_INFO_TYPE` probe) return `NOT_SUPPORTED` and the kernel continues.

The one input this environment cannot produce is the **kernel `Image`** (no aarch64 Linux
cross-toolchain here), so it comes from `$BALEEN_LINUX_DIR` — an official Alpine `virt` kernel,
decompressed from its EFI-zboot wrapper. `hv-metal/linux/fetch-guest-image.sh` builds it; see §5f.
**No isolation content** (the thesis is proven on the un-forgeable synthetic guests); this demonstrates
the proven interface carries an unmodified kernel. The guest CPU is a stable `cortex-a72` baseline, not
`-cpu max` — `max` advertises features (S1PIE, SME, GCS, pauth) whose EL1 use traps to EL2 for a
hypervisor to enable, which this minimal EL2 deliberately does not.

## 5f — the capstone becomes a gate (⑬)

For several arcs this boot was a **local result**: kernel-gated on a hand-made `$BALEEN_LINUX_DIR`
that one laptop could produce, run by a command that asserted nothing (`qemu-linux` returned QEMU's
exit status), and deliberately outside CI. That is a demonstration nobody can re-run. It is now the
`real-linux boot (QEMU)` job.

**This carries no isolation content**, and it is not a rung. It was deferred for exactly that reason.
Its whole justification is sequencing: the two-real-guests capstone would otherwise land the same way
— an anecdote rather than something a gate re-runs.

**Reproducing the artifacts.** `hv-metal/linux/fetch-guest-image.sh` downloads two VERSION-PINNED
official Alpine URLs, verifies each against a SHA-256 recorded in the script, unwraps the EFI-zboot
`vmlinuz-virt` into the raw arm64 `Image` the boot protocol wants, and builds the initramfs from the
official minirootfs plus the checked-in `hv-metal/linux/guest-init.sh` as `/init`. So what any of this
trusts is a set of fixed 256-bit hashes; `dl-cdn.alpinelinux.org` is an *availability* dependency, not
a *trust* one. The `Image` is bit-reproducible (a byte slice plus gunzip of upstream's own bytes) and
is therefore pinned too, so a cached copy is checked rather than believed; the cpio archive is not
(it records mtimes and uids), so its *inputs* are pinned instead. There is one recipe: CI runs the
same script a developer with an empty `$BALEEN_LINUX_DIR` runs.

**What the job asserts.** `cargo xtask qemu-linux-test` runs the same QEMU line as the demo — one
`linux_qemu_args`, so the gate cannot pass against a boot the demo does not perform — with the serial
output captured, requiring every marker in `LINUX_MARKERS` and none in `LINUX_FORBIDDEN`. The per-marker
reasoning lives on those constants. Two are worth repeating here:

- **`node   0: [mem 0x0000000048000000-0x000000007fffffff]`** is the memory contract in one string.
  It is the kernel reporting the window it read from *our* DTB, and it must equal `LINUX_RAM_BASE..
  LINUX_RAM_END` (what the emitter maps) and xtask's `-device loader` addresses (where the blobs
  land). Four places that have to agree, previously kept in agreement by hand.
- **`baleen: LINUX GUEST TRAP`** is forbidden. `handle_linux_sync` prints it for any lower-EL
  synchronous exception that is not an `HVC` — i.e. for every Stage-2 abort — so an emitter
  mis-mapping lands there. It is what makes this an assertion about the emitter rather than about
  Linux.

**Probed load-bearing before the job was written** (design-lessons #65, #70): ten mutations, ten red —
the DTB's `/memory` base; the emitted RAM window (`LINUX_RAM_END`); the pass-through device window;
xtask's initramfs load address; the kernel entry address; read-only guest-RAM leaves (this is the one
that produces `LINUX GUEST TRAP`, `EC=0x20` at `0x4800_0000`); the wait cap on a boot that does not
finish; absent artifacts; a flipped checksum pin; and a substituted `Image` under a matching stamp.

**The failure mode this accepts.** As a required check, a mirror outage blocks merges. That is the
price of the alternative being decorative. What is deliberately not done is letting a fetch failure
pass green — a job that goes green when it could not obtain the kernel would stay green if the kernel
were deleted (design-lesson #71).

**Measured cost (PR #97, the job's first run): 49 s end to end on a COLD cache** — 11 s of apt, 3 s to
fetch/checksum/unwrap both artifacts, 15 s for the boot including the hv-metal cross-build. About what
the synthetic `metal boot (QEMU)` job costs (42 s), so being required is cheap. The cache is an outage
hedge rather than a speed one.

**Reproduced independently on the runner**, which is the part worth keeping: the x86-64 Linux runner's
unwrap produced `Image` sha256 `8b216f74…` — byte-identical to the macOS/arm64 laptop's — and all
eleven markers appeared under the runner's **QEMU 8.2**, a different QEMU generation from the local
11.0.3. Two hosts, two architectures, two QEMU generations, one result. (The cpio archive differs in
size between them, 4029394 vs 4021398 bytes, exactly as the non-reproducibility note above predicts —
and it does not matter, because its inputs are what is pinned.)

## 5g — the guest's console stops being the machine's (③-a1)

**Say what this is: INTEGRATION, boot-witnessed, not a machine-checked rung.** It is the first step of
③ (two real guests), and it is deliberately a different kind of work from the twelve merges that
preceded it. It touches `hv-metal` only, so it green-skips the Kani/Verus gates.

**The ledger named the wrong blocker.** ③ was recorded as blocked on the singular hardcoded guest-RAM
window. That is real but it is a rename. The blocker that is a *rewrite* is device ownership: §5e's
guest owns the **real** PL011 and the **real** GIC (`IMO=0`, pass-through, `guest.dts` handing it
`pl011@9000000` as `stdout-path`), and two guests cannot both own one UART. `linux.rs`'s own module
doc said as much and nobody had cashed it.

**The probe that inverted the obvious call.** Reusing `crate::virtio`'s proven console — the ring as
a grant — was the natural move and is **impossible** with an unmodified kernel: the shipped Alpine
`-virt` config has `CONFIG_VIRTIO_MMIO=m`, a module, and this initramfs ships no `/lib/modules`, so
the built-in `CONFIG_VIRTIO_CONSOLE=y` has no bus to attach to. A console that appears only after
userspace loads modules is not a console. `CONFIG_SERIAL_AMBA_PL011=y` and `_CONSOLE=y` *are* built
in — so emulating the device the guest already believes it has works from the first `earlycon` byte,
and it retracts the predicted cost of losing `earlycon`.

**What landed.**

1. **An `EC=0x24` data-abort path in `handle_linux_sync`.** Before this, `HVC` was serviced and every
   other trap was fatal — no mediated device could exist. The `ESR_EL2.ISS` field decode now lives in
   `hv-metal/src/abort.rs`, shared with the synthetic guest's virtio path, because two decodes of one
   architectural fact is exactly the shape ⑭ spent a rung removing.
2. **The pass-through window shrank 32 MiB → 16 MiB**, and is now *derived* from the GIC's own
   addresses (`gic::GICD_BASE .. gic::GICR_END`) rather than written as a pair of literals. On QEMU
   `virt` the redistributor region ends at exactly `0x0900_0000`, so the PL011 falls out of the window
   with **`guest.dts` completely unchanged**.
3. **`hv-metal/src/vpl011.rs`** — a PL011 register file in EL2, transmit bytes relayed to the real
   UART. `unsafe`-free (it hands the caller a byte rather than touching MMIO). The AMBA bus probe
   binds against its identification registers: the guest reports
   `9000000.pl011: ttyAMA0 at MMIO 0x9000000 … is a PL011 rev1`.

**Two facts the COMPILER now checks**, because a boot marker can only witness what a boot exercises:
the emulated PL011 sits at the machine's real PL011 address, and **the pass-through window does not
cover it**. Restoring the 32 MiB window is a build error, not a silent return to pass-through.

**The witness, and why the existing ten markers could not be it.** Every §5f marker is a statement
about the kernel, and the kernel prints the same bytes whether its UART is emulated or passed
through. **Measured: with the 32 MiB window restored (and the compile-time assertion defeated), ten
of the twelve markers stayed green.** So the device model produces its own: it watches its `DR`
stream for userspace's `BALEEN-STEP0-OK` and reports at `SYSTEM_OFF`. That claim is deliberately
**ingress** — a probe that deleted the relay to the real UART left it green while seven kernel
markers went red, so the wording was corrected to say what the mechanism checks. The egress half is
those seven, which the kernel cannot print unless the emulator relays them.

**Probed load-bearing: six mutations, six red.** The 32 MiB window (a *compile* error; with the
assertion defeated, three assertions red including the new forbidden `vpl011 FAIL` reporting
`0 register traps`) · removing the `EC=0x24` arm (nine red, `LINUX GUEST TRAP` fires) · dropping the
relay to the real UART (seven red) · skipping the `ELR_EL2` advance (the guest re-executes the
faulting store forever; the boot times out) · using `FAR_EL2` as the fault IPA instead of
`HPFAR_EL2` (timeout) · writing the load result into the wrong guest register (timeout).

**The address arithmetic is not the synthetic path's, and probe 5 is why.** `guest.rs` takes the whole
faulting address from `FAR_EL2`, sound *there* because the synthetic guests run stage-1 off. A real
kernel enables its MMU within milliseconds, after which `FAR_EL2` holds a guest **virtual** address —
the probe-2 trap report shows `FAR=0xffffffffff5fd018`. The IPA comes from `HPFAR_EL2` (`IPA[47:12]`)
joined with `FAR_EL2[11:0]` for the in-page register offset, which a 4 KiB granule leaves untranslated.

**Behaviour, measured.** The kernel's 200-line boot log is line-for-line identical to a `main`
worktree's; the only changes are the window marker (32 → 16 MiB) and the new witness line. 30 621
register traps, 11 436 bytes relayed, and the local gate goes from ~1 s to ~2 s.

**Declared residue, not hidden.** There is **no receive**: `FR.RXFE` is permanently set, because
delivering a received byte means delivering an *interrupt* and this rung keeps `IMO=0`. The guest is
non-interactive (its `/init` prints markers and powers off), so neither the demo nor the gate needs
it, but a human typing at `cargo xtask qemu-linux` will not be heard until **③-a2** (`IMO=1` + vGIC
list-register injection, reusing Arcs 7a–8b/III-3). **③-b** — the second RAM window, the second
guest, and each faulting on the peer's memory — is where the thesis content is; ③-a exists to make
③-b a one-variable change.

## Scope and honesty

- **Plumbing, no isolation content.** Arc 5 adds capabilities; the thesis (Arc 0–4) is untouched.
- **Single-guest-per-phase.** Each phase runs one interrupt-capable guest; the vGIC list-register state
  is per-CPU EL2 context. Scheduling *multiple* interrupt-capable guests concurrently would make the
  `ICH_*` state part of the per-vCPU context to save/restore on a switch (like `GuestContext` for GPRs) —
  a named forward obligation, not needed for Arc 5's model. See Audit #7.
- `hv-core`/`hv-hal` untouched. Every `unsafe` is EL2-legal GIC/timer register or GIC MMIO access.
