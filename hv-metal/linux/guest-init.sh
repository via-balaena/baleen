#!/bin/sh
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Via Balaena
#
# The real-Linux capstone guest's `/init` — PID 1 inside the initramfs `fetch-guest-image.sh` builds
# from the official Alpine minirootfs. It runs as the FIRST userspace process of a real, unmodified
# Alpine kernel booted at EL1 behind hv-metal's proven Stage-2 emitter (M5 Arc 5e / Arc 6b).
#
# Every line here exists to print a marker `cargo xtask qemu-linux-test` asserts, and each marker is
# a witness produced BY a mechanism rather than a claim about one (design-lesson #24f):
#
#   * BALEEN-STEP0-OK        the kernel unpacked THIS initramfs from the `-device loader` PA
#                            (0x4c00_0000) and executed it — so guest RAM is readable at that address
#                            through the emitted Stage-2 map, and userspace is alive.
#   * baleen-guest-ram:      the guest's OWN view of its RAM window, read out of /proc/iomem. It must
#                            equal THIS guest's HALF of the window — `guest_ram_base(slot)` for
#                            `LINUX_SUP_FRAMES_PER_GUEST` frames, out of hv-metal/src/stage2.rs —
#                            together with the /memory node xtask renders into this guest's own DTB
#                            and the `-device loader` address its Image went to. One string, four
#                            places: "the memory contract" checked from inside. (It said
#                            `LINUX_RAM_BASE..LINUX_RAM_END` in linux.rs until ③-b2b-ii-b; ③-b2a had
#                            already halved the window and moved the constants, and this outlived
#                            both — which is why the marker itself carries the values.)
#   * baleen-spi-intid:      ⑱-6. The GIC INTID the GUEST says its UART uses, bound by the gate to
#                            `WITNESS_SPI` in linux.rs — two artifacts naming one interrupt, with
#                            neither taking the other's word for which.
#   * baleen-spi-affinity:   ⑱-6. That the kernel ACCEPTED the affinity change, so a failed write
#                            cannot masquerade as a routing that was never honoured.
#   * baleen-spi-counts:     ⑱-6, and the property itself: which of the guest's OWN CPUs ran the
#                            handler for the INTID it re-aimed. `cpu0=0 cpu1=1` is honoured routing;
#                            `cpu0=1 cpu1=0` is what ignoring `GICD_IROUTER` produces, which is
#                            exactly what the `spi-route-probe` build measures.
#   * BALEEN-IDLE-START/END  ⑱-4b-i, and the ODD ONE OUT: this pair brackets a second of deliberate
#                            idleness, so what it witnesses is not the printing but what happens
#                            BETWEEN the two lines — the kernel running out of work and executing
#                            `wfi`. See the block above it for the measurement that made it
#                            necessary. A boot that prints START and never END is a guest that went
#                            idle and was never given the pCPU again, which is exactly the
#                            starvation `report_idle`'s kill probe induces.
#   * poweroff               busybox `poweroff -f` -> the kernel's PSCI SYSTEM_OFF -> HVC -> hv-metal's
#                            EL2 handler. The end-to-end round trip, and how the boot terminates.
#
# `poweroff -f` is deliberately the last line: if it is ever not reached, the boot hangs and the test
# fails on its wait cap rather than passing on a partial run.

/bin/busybox mount -t proc     proc /proc 2>/dev/null
/bin/busybox mount -t sysfs    sys  /sys  2>/dev/null
/bin/busybox mount -t devtmpfs dev  /dev  2>/dev/null

echo ""
echo "########## BALEEN-STEP0-OK ##########"
/bin/busybox uname -a
echo "baleen-guest-ram: $(/bin/busybox grep -m1 'System RAM' /proc/iomem | /bin/busybox tr -d ' ')"
echo "cmdline: $(/bin/busybox cat /proc/cmdline)"

# ★★ ⑱-6 — **THE GUEST AIMS ITS OWN INTERRUPT AT ITS SECOND CPU, and the hypervisor obeys.**
#
# This is the only block here that asks the kernel to *decide* something rather than report it, and
# the decision is the witness. Writing an affinity mask makes arm64 Linux's `gic_set_affinity` write
# `GICD_IROUTER<n>` — a trap into hv-metal's emulated distributor — after which EL2 delivers that
# INTID to the vCPU the guest named instead of to whichever vCPU happens to be on the pCPU.
#
# Until ⑱-6 the routing was **recorded and honoured by nothing**, which was correct while a guest had
# one vCPU and silently wrong once it had two.
#
# ⚠ **The IRQ number is LOOKED UP, not hardcoded.** `/proc/interrupts` prints the kernel's own IRQ
# number beside the GIC INTID, so this resolves `uart-pl011` to whatever Linux numbered it and the
# marker below carries the INTID that EL2 independently names (`WITNESS_SPI` in linux.rs). Two
# artifacts, one interrupt, neither taking the other's word for which.
#
# ⚠ **`2` is CPU1's mask, and the choice is load-bearing**: Linux points every SPI at the boot CPU
# during `gic_dist_init`, so routing to CPU0 would be indistinguishable from EL2 ignoring the
# register entirely. The `sleep 1` below is what gives CPU1 the pCPU to take it.
#
# MEASURED baseline on `main` before this was written (design-lesson #186): this row is
# `13:  0  0  GICv3  33 Level  uart-pl011` — **zero on both CPUs across a whole boot**, because the
# emulated PL011 never raises. So a count appearing here is EL2's injection and can be nothing else,
# and WHICH COLUMN it appears in is the entire property.
baleen_irq=$(/bin/busybox grep uart-pl011 /proc/interrupts | /bin/busybox cut -d: -f1 | /bin/busybox tr -d ' ')
# ⚠ **INTID FIRST, Linux's own IRQ number in parentheses, and the order is what makes this
# assertable.** The gate requires `baleen-spi-intid: 33`, which binds the GIC INTID the GUEST reports
# to `WITNESS_SPI` in linux.rs — so changing one without the other goes red. The Linux IRQ number is
# an allocation detail that may legitimately move, so it is deliberately outside the asserted prefix.
echo "baleen-spi-intid: $(/bin/busybox grep uart-pl011 /proc/interrupts | /bin/busybox awk '{print $5}') (linux irq ${baleen_irq})"
echo 2 > /proc/irq/${baleen_irq}/smp_affinity
echo "baleen-spi-affinity: $(/bin/busybox cat /proc/irq/${baleen_irq}/smp_affinity)"

# ★★ ⑱-4b-i — **GO IDLE ON PURPOSE, and this line is a WITNESS-ENABLING MECHANISM, not padding.**
#
# Every other line here prints a marker. This one produces a *scheduler state* instead: with PID 1
# asleep and nothing else runnable, the kernel has no work, so it idles into `wfi` — the trap
# `HCR_EL2.TWI` routes to EL2 and the whole reason `handle_linux_wfi` exists.
#
# ⚠ **Without it that path is very nearly untested, which was MEASURED before this line was added.**
# Six boots of the previous init on `main`: dom 1 / dom 2 trapped (1,0) (0,0) (0,0) (1,1) (0,1)
# (1,1) `wfi`s — **two of the six trapped ZERO across both guests**, and the most any boot managed
# was two. A witness over that is vacuous a third of the time and a kill probe over it cannot kill.
#
# With one second of sleep the guests idle **hundreds of times each**, reliably, every boot. That is
# what makes the ⑱-4b-i witness an assertion rather than a coin flip, and it is what let the
# ping-pong that rung fixes be measured on `main` instead of argued about — with this sleep and
# `SchedPreempt` still in place, the same boot produced **8,735 yields per guest**; with `SchedBlock`
# it produced 81. ⚠ That "after" figure is ⑱-4b-i's, at one vCPU per guest; once ⑱-4b-ii started a
# second one the same boot blocks ~465 times across four vCPUs, because there is far more idling to
# do. The 8,735 is the number that matters and it is a statement about `main`.
# See `report_idle` in hv-metal/src/linux.rs for the current split and what it means.
#
# One second, not more. The trap count scales roughly linearly with the sleep — the guests idle at
# their own tick rate — so a longer sleep buys proportionally more of a signal that is already large
# enough, at ~1 s of gate time per boot configuration.
echo "########## BALEEN-IDLE-START ##########"
/bin/busybox sleep 1
echo "########## BALEEN-IDLE-END ##########"

# ⑱-6, the other half: **the guest's own accounting of where the interrupt landed.**
#
# `/proc/interrupts` counts per CPU, so this row is the kernel saying which of ITS processors took
# the INTID it re-aimed above — an answer produced by the guest's interrupt path, not by anything
# EL2 asserts about itself. `cpu0=0 cpu1=1` is the property; `cpu0=1 cpu1=0` is precisely what
# ignoring `GICD_IROUTER` looks like, which is what the removed-fix probe produces.
echo "baleen-spi-counts: $(/bin/busybox grep uart-pl011 /proc/interrupts | /bin/busybox awk '{print "cpu0=" $2 " cpu1=" $3}')"

echo "########## poweroff ##########"

/bin/busybox poweroff -f
