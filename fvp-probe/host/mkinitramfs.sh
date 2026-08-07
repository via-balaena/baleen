#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Via Balaena
#
# Build the BASE initramfs that carries Arm's model into a Linux VM: an Ubuntu Base userspace plus
# the FVP package. Run after `fetch-fvp.sh`, before `run-fvp.sh`.
#
# ── WHY AN INITRAMFS, AND NOT A DISK IMAGE ───────────────────────────────────────────────────────
#
# ★ This is the trick that makes the whole route cheap, and it is worth understanding before
# "improving" it. The kernel we boot is `.baleen-linux/Image` — the SAME checksum-pinned Alpine
# kernel the real-Linux gate uses, already on disk, costing nothing extra. That kernel ships with
# **no modules**. So it has no virtio-blk driver to mount a root disk with, no 9p to share a host
# directory, and no network.
#
# An initramfs needs none of them: the kernel unpacks it into tmpfs BEFORE any driver runs. So the
# route is 28 MiB of Ubuntu Base rather than a multi-hundred-megabyte cloud image, and it reuses an
# artifact the repo already pins instead of introducing a new one.
#
# ── WHY THE ARCHIVE IS SPLIT IN TWO ──────────────────────────────────────────────────────────────
#
# This script builds only `base.cpio.gz` (~200 MB of model and userspace, slow, and identical from
# run to run). `run-fvp.sh` builds a few-kilobyte `payload.cpio.gz` holding the probe binary and
# `/init`, and simply CONCATENATES the two: Linux unpacks concatenated gzipped cpio archives in
# order, later entries winning, which is the same mechanism early-microcode initramfs images use.
#
# The point is the iteration loop. Re-cpio-ing 200 MB to change ten lines of a bare-metal probe
# would dominate every cycle; concatenating a 4 KB archive onto a cached one does not. `/init` lives
# in the PAYLOAD for exactly this reason — it is a file we expect to keep editing.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FVP_DIR="${BALEEN_FVP_DIR:-${REPO_ROOT}/.fvp}"
STAGE="$FVP_DIR/stage"
BASE_CPIO="$FVP_DIR/base.cpio.gz"

UBUNTU_BASE="ubuntu-base-24.04.4-base-arm64.tar.gz"
LIBATOMIC_DEB="libatomic1_14.2.0-4ubuntu2~24.04.1_arm64.deb"

for f in "$UBUNTU_BASE" "$LIBATOMIC_DEB"; do
    [[ -f "$FVP_DIR/$f" ]] || { echo "missing $FVP_DIR/$f — run fvp-probe/host/fetch-fvp.sh first" >&2; exit 1; }
done
PKG="$FVP_DIR/pkg/Base_RevC_AEMvA_pkg"
[[ -d "$PKG" ]] || { echo "missing $PKG — run fvp-probe/host/fetch-fvp.sh first" >&2; exit 1; }

# ─── skipping ────────────────────────────────────────────────────────────────────────────────────
#
# Rebuild only when an INPUT changed, identified by content rather than by "the file exists" — the
# shape where a check's inputs cannot discriminate (design-lesson #71), and the same reason
# `fetch-guest-image.sh` stamps its recipe rather than testing for the artifact.
RECIPE="$(shasum -a 256 "$FVP_DIR/$UBUNTU_BASE" "$FVP_DIR/$LIBATOMIC_DEB" "$0" | shasum -a 256 | cut -d' ' -f1)"
STAMP="$FVP_DIR/.base.stamp"
if [[ "${1:-}" != "--force" ]] && [[ -f "$BASE_CPIO" ]] && [[ -f "$STAMP" ]] && [[ "$(cat "$STAMP")" == "$RECIPE" ]]; then
    echo "mkinitramfs: base.cpio.gz is current ($(du -h "$BASE_CPIO" | cut -f1)); --force to rebuild"
    exit 0
fi

echo "mkinitramfs: staging"
rm -rf "$STAGE"
mkdir -p "$STAGE"

# 1. The userspace. glibc, because the model's bundled shared objects will not load against musl —
#    which is why Alpine's own rootfs is not reused here even though its kernel is.
tar xzf "$FVP_DIR/$UBUNTU_BASE" -C "$STAGE"

# 2. libatomic1. A TRANSITIVE dependency of a bundled `.so`, absent from the model executable's own
#    DT_NEEDED, so `ldd` on the binary does not reveal it and the failure it causes appears at
#    dlopen time rather than at start-up.
tmp="$(mktemp -d)"
( cd "$tmp" && ar x "$FVP_DIR/$LIBATOMIC_DEB" && zstd -dc data.tar.zst | tar x -C "$STAGE" )
rm -rf "$tmp"

# 3. The model. Only `models/` (the simulator and its libraries) and `fmtplib/` (the GCC 9.3
#    libstdc++/libgcc it was built against — Ubuntu 24.04's are newer and would probably work, but
#    "probably" is not a thing to spend a debugging session on). Deliberately EXCLUDED: `doc/` (24
#    MB of PDFs — read them on the host, not in the VM), `bin/` (43 MB of model_shell and the Qt
#    debugger) and `plugins/` (23 MB, all trace plugins we do not use). That is 90 MB kept out of
#    every boot. `license_terms/` is small and is copied because §2.3 requires preserving the
#    copyright notices.
mkdir -p "$STAGE/opt/fvp"
cp -R "$PKG/models"        "$STAGE/opt/fvp/"
cp -R "$PKG/fmtplib"       "$STAGE/opt/fvp/"
cp -R "$PKG/license_terms" "$STAGE/opt/fvp/"

# 4. Mount points. Ubuntu Base ships an EMPTY /dev — no console, no null — which is why `/init`
#    mounts devtmpfs before it tries to print anything. Creating the device nodes here is not an
#    option: `mknod` needs root, and this script deliberately does not.
mkdir -p "$STAGE/proc" "$STAGE/sys" "$STAGE/dev" "$STAGE/tmp" "$STAGE/run"

echo "mkinitramfs: packing $(du -sh "$STAGE" | cut -f1) (this is the slow part, and it is cached)"
( cd "$STAGE" && find . -print0 | cpio --null -o -H newc --quiet ) | gzip -1 > "$BASE_CPIO"
echo "$RECIPE" > "$STAMP"

echo "mkinitramfs: OK — $BASE_CPIO ($(du -h "$BASE_CPIO" | cut -f1))"
echo "  next: fvp-probe/host/run-fvp.sh"
