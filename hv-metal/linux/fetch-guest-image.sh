#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Via Balaena
#
# Build the real-Linux capstone's guest artifacts — a raw arm64 kernel `Image` and an initramfs —
# from OFFICIAL, CHECKSUM-PINNED Alpine downloads. This is the single derivation of those artifacts
# (design-lesson #14c): CI runs it, and so does a developer with an empty `$BALEEN_LINUX_DIR`. Before
# this script the directory was a hand-made black box that only one laptop could reproduce, which is
# not a thing a merge gate may depend on.
#
#   $ hv-metal/linux/fetch-guest-image.sh          # populate $BALEEN_LINUX_DIR
#   $ cargo xtask qemu-linux                       # the interactive demo
#   $ cargo xtask qemu-linux-test                  # the headless, marker-asserting gate
#
# ── WHAT THIS TRUSTS ─────────────────────────────────────────────────────────────────────────────
#
# Two fixed 256-bit hashes, checked below. `dl-cdn.alpinelinux.org` is an AVAILABILITY dependency,
# not a TRUST dependency: it serves the bytes, and it cannot substitute different ones without the
# job failing loudly. That is the same posture as the SHA-pinned GitHub Actions in
# .github/workflows/ (a moved tag cannot silently change what runs) applied to a downloaded blob.
#
# Both URLs are VERSION-PINNED IN THE PATH (`netboot-3.24.1/`, `alpine-minirootfs-3.24.1-`), not
# rolling aliases like `netboot/vmlinuz-virt`, so their content is stable for the life of the branch.
# Raising the version is a deliberate edit: change ALPINE_* below, re-run, re-record the hashes, and
# re-run `cargo xtask qemu-linux-test`.
#
# ── WHAT IT PRODUCES ─────────────────────────────────────────────────────────────────────────────
#
#   Image                 the raw arm64 kernel the arm64 boot protocol wants, unwrapped from Alpine's
#                         EFI-zboot `vmlinuz-virt`. BIT-REPRODUCIBLE: the unwrap is a byte slice plus
#                         gunzip, so this is upstream's kernel unmodified, and two runs agree.
#   custom-initramfs.gz   the Alpine minirootfs plus `guest-init.sh` as /init, as a newc cpio.gz. NOT
#                         bit-reproducible (cpio records mtimes and uids); its CONTENTS are, and the
#                         only file that is not upstream's is the checked-in /init.
#   .stamp                the recipe identity (see SKIPPING, below).
#
# ── SKIPPING ─────────────────────────────────────────────────────────────────────────────────────
#
# A rebuild is skipped only when `.stamp` matches the CURRENT recipe — the versions AND both pinned
# hashes AND the /init hash. A bare "the files exist" check would let a stale or cached artifact
# satisfy the gate, which is the failure mode where a check's inputs cannot discriminate (#71): the
# job would stay green against the wrong kernel. `--force` rebuilds regardless.
set -euo pipefail

# ─── the pins ────────────────────────────────────────────────────────────────────────────────────
ALPINE_BRANCH="v3.24"
ALPINE_VERSION="3.24.1"
ALPINE_MIRROR="https://dl-cdn.alpinelinux.org/alpine"

KERNEL_URL="${ALPINE_MIRROR}/${ALPINE_BRANCH}/releases/aarch64/netboot-${ALPINE_VERSION}/vmlinuz-virt"
KERNEL_SHA256="47970e0ee0478fe5c60824a89f162d5a353fa29466e5d3bddb0f9c506f1ed756"

ROOTFS_URL="${ALPINE_MIRROR}/${ALPINE_BRANCH}/releases/aarch64/alpine-minirootfs-${ALPINE_VERSION}-aarch64.tar.gz"
ROOTFS_SHA256="f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259"

# The unwrapped kernel. The unwrap is a byte slice plus gunzip, so this is DERIVED — but recording it
# lets the check below run on EVERY path, including one where `Image` arrived from a CI cache rather
# than from this script. Without it the gate's kernel would be whatever the cache held, which is the
# shape where a check's inputs cannot discriminate (#71). There is no equivalent pin for the
# initramfs: cpio records mtimes and uids, so the archive is not bit-reproducible. Its INPUTS are
# pinned instead (ROOTFS_SHA256 plus the checked-in guest-init.sh, both in the stamp).
IMAGE_SHA256="8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd"

# Bump when the recipe itself changes shape (not merely its pins) so cached artifacts are rebuilt.
RECIPE_VERSION="1"

here="$(cd "$(dirname "$0")" && pwd)"
init_src="$here/guest-init.sh"

force=0
[ "${1:-}" = "--force" ] && force=1

dir="${BALEEN_LINUX_DIR:-$HOME/forge/baleen-metal-linux/alpine}"
mkdir -p "$dir"

# ─── portable helpers ────────────────────────────────────────────────────────────────────────────
# `sha256sum` on Linux, `shasum -a 256` on macOS — the script must run in both places or it is not
# one derivation.
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# Read a little-endian u32 at byte offset $2 of file $1. `od` is POSIX; `-t u4` needs 4-byte
# alignment, which every offset we read has.
u32_at() { od -A n -t u4 -j "$2" -N 4 "$1" | tr -d ' \n'; }

# Read $3 bytes of file $1 starting at byte offset $2. `tail -c +N` is 1-based, and it is orders of
# magnitude faster than `dd bs=1` (measured: 0.3 s vs. minutes for a 10 MB payload).
#
# `set +o pipefail` inside the subshell is LOAD-BEARING, not tidying: `head` closes the pipe as soon
# as it has its $3 bytes, `tail` takes SIGPIPE (141), and under the script's `pipefail` + `set -e`
# that kills the run right after the download with no message at all. Scoped to the subshell so the
# rest of the script keeps pipefail. A read that genuinely fails yields empty output, which the magic
# checks at both call sites then reject by name.
slice() { ( set +o pipefail; tail -c "+$(( $2 + 1 ))" "$1" | head -c "$3" ); }

die() { echo "fetch-guest-image: $*" >&2; exit 1; }

fetch() {
    local url="$1" out="$2" want="$3" got
    echo "fetch-guest-image: downloading $url"
    curl -fsSL --retry 3 --retry-delay 5 --max-time 900 -o "$out" "$url" \
        || die "download FAILED: $url (network, or the pinned version was withdrawn upstream)"
    got="$(sha256 "$out")"
    [ "$got" = "$want" ] || die \
        "checksum MISMATCH for $url
  expected $want
  got      $got
The pinned bytes are not what the mirror served. Do NOT 'fix' this by pasting the new hash without
establishing why it changed: a version-pinned Alpine URL is not supposed to change content."
    echo "fetch-guest-image: sha256 OK ($got)"
}

# ─── skip if the artifacts already match THIS recipe ──────────────────────────────────────────────
stamp_want="recipe=${RECIPE_VERSION} alpine=${ALPINE_VERSION} kernel=${KERNEL_SHA256} rootfs=${ROOTFS_SHA256} image=${IMAGE_SHA256} init=$(sha256 "$init_src")"
stamp_file="$dir/.stamp"

if [ "$force" -eq 0 ] \
    && [ -f "$dir/Image" ] && [ -f "$dir/custom-initramfs.gz" ] && [ -f "$stamp_file" ] \
    && [ "$(cat "$stamp_file")" = "$stamp_want" ]; then
    # The stamp says the recipe matches; the hash says the BYTES do. Both, because the stamp travels
    # with the artifacts through a CI cache and would happily vouch for a substituted Image.
    got="$(sha256 "$dir/Image")"
    if [ "$got" = "$IMAGE_SHA256" ]; then
        echo "fetch-guest-image: $dir is already current for this recipe (Image sha256 $got) — nothing to do (--force to rebuild)"
        exit 0
    fi
    echo "fetch-guest-image: $dir/Image does not match the pinned hash ($got) — rebuilding" >&2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# ─── 1. the kernel: unwrap Alpine's EFI-zboot vmlinuz into a raw arm64 Image ─────────────────────
#
# The arm64 boot protocol (and hv-metal's `eret` into `ELR_EL2 = 0x4800_0000`) wants a RAW `Image`.
# Alpine ships `vmlinuz-virt` as an EFI-zboot PE wrapper around a compressed Image, whose header is:
#
#   +0x00  u32   "MZ\0\0"            PE/COFF DOS magic
#   +0x04  u8[4] "zimg"              the zboot marker
#   +0x08  u32   payload_offset
#   +0x0c  u32   payload_size
#   +0x18  char[32] compression      "gzip" for Alpine's arm64 kernels
#
# QEMU's `-device loader,force-raw=on` deposits whatever bytes it is given, so handing it the wrapper
# loads a PE header at the kernel entry point and the guest faults immediately. (Handing the wrapper
# to `-kernel` instead reports "unable to handle corrupt EFI zboot image" — a different, louder
# failure, and how this was originally diagnosed.)
#
# The magic and the compression string are both CHECKED rather than assumed: if upstream switches to
# zstd or lz4, this must say so, not silently emit a garbage Image that fails later as a mystery.
fetch "$KERNEL_URL" "$work/vmlinuz-virt" "$KERNEL_SHA256"

zimg="$(slice "$work/vmlinuz-virt" 4 4)"
[ "$zimg" = "zimg" ] || die "vmlinuz-virt is not an EFI-zboot image (magic at +4 = '$zimg', want 'zimg')"

comp="$(slice "$work/vmlinuz-virt" 24 4)"
[ "$comp" = "gzip" ] || die "EFI-zboot payload is '$comp'-compressed, not gzip — this script only unwraps gzip"

payload_offset="$(u32_at "$work/vmlinuz-virt" 8)"
payload_size="$(u32_at "$work/vmlinuz-virt" 12)"
echo "fetch-guest-image: zboot payload: offset=$payload_offset size=$payload_size ($comp)"

slice "$work/vmlinuz-virt" "$payload_offset" "$payload_size" | gunzip -c > "$work/Image" \
    || die "gunzip of the zboot payload failed"

# The arm64 Image header carries its magic at +0x38: u32 LE 0x644d5241, i.e. the bytes "ARMd".
# Checking it here means a bad unwrap is caught by THIS script, naming the reason, rather than as a
# silent guest hang later.
img_magic="$(slice "$work/Image" 56 4)"
[ "$img_magic" = "ARMd" ] || die "unwrapped payload is not an arm64 Image (magic at +0x38 = '$img_magic', want 'ARMd')"

img_sha="$(sha256 "$work/Image")"
[ "$img_sha" = "$IMAGE_SHA256" ] || die \
    "unwrapped Image sha256 MISMATCH
  expected $IMAGE_SHA256
  got      $img_sha
The download matched its pin, so the wrapper is upstream's — the unwrap changed. Re-derive
IMAGE_SHA256 deliberately, and re-run \`cargo xtask qemu-linux-test\` before recording it."
echo "fetch-guest-image: Image OK — $(wc -c < "$work/Image" | tr -d ' ') bytes, sha256 $img_sha"

# ─── 2. the initramfs: the official minirootfs + our /init ───────────────────────────────────────
fetch "$ROOTFS_URL" "$work/minirootfs.tar.gz" "$ROOTFS_SHA256"

stage="$work/stage"
mkdir -p "$stage"
tar -xzf "$work/minirootfs.tar.gz" -C "$stage"
[ -x "$stage/bin/busybox" ] || die "the minirootfs has no /bin/busybox — guest-init.sh drives everything through it"

cp "$init_src" "$stage/init"
chmod 0755 "$stage/init"

# `cpio -o -H newc` is the format the kernel's initramfs unpacker reads. Run from inside the stage so
# the archive holds relative paths (`./init`, not `/tmp/xxx/init`), or the kernel unpacks nothing and
# panics with "No working init found".
( cd "$stage" && find . -print | cpio -o -H newc --quiet 2>/dev/null || ( cd "$stage" && find . -print | cpio -o -H newc ) ) \
    | gzip -9 > "$work/custom-initramfs.gz"
echo "fetch-guest-image: initramfs OK — $(wc -c < "$work/custom-initramfs.gz" | tr -d ' ') bytes"

# ─── 3. publish ──────────────────────────────────────────────────────────────────────────────────
# Written last and together, so an interrupted run leaves the previous (working) pair in place rather
# than a half-updated directory that boots to something nobody chose.
mv "$work/Image" "$dir/Image"
mv "$work/custom-initramfs.gz" "$dir/custom-initramfs.gz"
printf '%s' "$stamp_want" > "$stamp_file"

echo "fetch-guest-image: done — $dir"
echo "  Image                $(wc -c < "$dir/Image" | tr -d ' ') bytes"
echo "  custom-initramfs.gz  $(wc -c < "$dir/custom-initramfs.gz" | tr -d ' ') bytes"
