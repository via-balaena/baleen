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
#                            equal `LINUX_RAM_BASE..LINUX_RAM_END` in hv-metal/src/linux.rs, the
#                            /memory node in guest.dts, and xtask's `-device loader` addresses. One
#                            string, four places — this is "the memory contract" checked from inside.
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
echo "########## poweroff ##########"

/bin/busybox poweroff -f
