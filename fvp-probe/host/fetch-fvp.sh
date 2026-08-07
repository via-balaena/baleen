#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Via Balaena
#
# Fetch the three host-side artifacts `fvp-probe` needs, into $BALEEN_FVP_DIR (default `.fvp/`).
#
#   $ fvp-probe/host/fetch-fvp.sh        # populate .fvp/
#   $ fvp-probe/host/mkinitramfs.sh      # build the VM image that runs the model
#   $ fvp-probe/host/run-fvp.sh          # build the probe, run it on the model, print the transcript
#
# ── WHY THIS FILE EXISTS AT ALL, WHICH IS THE POINT ──────────────────────────────────────────────
#
# On 2026-08-07 this harness was built in a session scratchpad and never checked in. The scratchpad
# is per-session, so by the next morning the tarball, the initramfs and every script were GONE, and
# the only surviving record was a prose recipe in a memory note. Reconstructing it cost more than
# writing it did.
#
# That is design-lesson #187 — a recorded obligation comes due silently — in its cheapest possible
# form: the obligation here was "keep the scripts", nothing enforced it, and nothing announced the
# loss. The fix is not discipline, it is putting the artifact where the repository keeps things.
#
# ── WHAT THIS IS NOT ─────────────────────────────────────────────────────────────────────────────
#
# ⛔ **NOT a CI gate, and it must not become one.** See `fvp-probe/README.md` for the argument in
# full; the short form is that the model cannot be cached or redistributed, so a gate would re-fetch
# ~91 MB from Arm on every run, and it executes at ~4.6 MIPS. The failure mode of such a gate is
# "`main` is red because Arm changed something". Every gate in this repo is pinned to bytes it can
# reproduce; this dependency cannot meet that bar, and pretending otherwise is worse than admitting
# it.
#
# ── WHAT THIS TRUSTS, STATED PRECISELY BECAUSE THE THREE PINS ARE NOT EQUALLY STRONG ─────────────
#
# * Ubuntu Base and libatomic1 are **corroborated**: their SHA-256s below were checked against
#   Ubuntu's own published `SHA256SUMS` and the signed `Packages` index respectively, not merely
#   recorded from the bytes that arrived here. Those are trust pins.
# * ⚠ **The FVP's hash is SELF-ATTESTED.** Arm publishes no checksum for this artifact, so the value
#   below is the SHA-256 of the download this file was written from — corroborated only by its size
#   matching the `Content-Length` Arm's CDN advertises (95 190 137 bytes). It detects corruption and
#   silent substitution *after* today; it cannot vouch for what was received on the first day. Do not
#   write it up as though it were the Alpine pins.
#
# ── LICENCE ──────────────────────────────────────────────────────────────────────────────────────
#
# Read first-hand from the package's own `doc/FastModels_FVP-BaseRevC_ReleaseNotes.txt`: the Base
# RevC "is freely available and does not require a license from Arm in order" to use. The bundled
# `license_terms/license_agreement.txt` is the *EULA for Arm Ecosystem Models* — NOT the Development
# Tools EULA that a web search finds first, which is a different and much longer document whose
# clause-2.2 analysis does not apply here. Note §2.4 forbids reverse engineering, decompiling,
# disassembly or alteration: recovering model parameters with `strings` is out, `--list-params` is in.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FVP_DIR="${BALEEN_FVP_DIR:-${REPO_ROOT}/.fvp}"

# ─── the pins ────────────────────────────────────────────────────────────────────────────────────

# Arm's version strings must be PROBED, not guessed: `11.24_11` resolves, while `11.27_19` and
# `11.29_27` both 404. Raising it is a deliberate edit — change these, re-run, re-record the hash,
# and re-run the probe, because the platform facts are the thing this instrument reads.
FVP_VERSION="11.24_11"
FVP_TARBALL="FVP_Base_RevC-2xAEMvA_${FVP_VERSION}_Linux64_armv8l.tgz"
FVP_URL="https://developer.arm.com/-/media/Files/downloads/ecosystem-models/${FVP_TARBALL}"
# ⚠ self-attested — see the header. NOT of the same strength as the two below.
FVP_SHA256="7a3593dafd3af6897b3a0a68f66701201f8f3e02a3d981ba47494b2f18853648"
FVP_BYTES="95190137"

# The model is an aarch64 Linux binary and there is no macOS build (`_MacOS`, `_Darwin` and
# `_macOS_armv8l` all 404), so on this laptop it runs inside a small QEMU/HVF VM. That VM needs a
# glibc userspace — Alpine's musl will not load the model's bundled `.so`s.
UBUNTU_BASE="ubuntu-base-24.04.4-base-arm64.tar.gz"
UBUNTU_URL="https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/${UBUNTU_BASE}"
UBUNTU_SHA256="04207713ece899c3740823d33690441ad3a7f0ded1101aca744e2b0f37ac7ff2"

# ⚠ ONE missing library, and it is a TRANSITIVE dependency — pulled in by a bundled `.so`, not named
# in the model binary's own DT_NEEDED, so `ldd` on the executable does not mention it. Everything
# else the package needs is either in Ubuntu Base (libc, libstdc++, libgcc_s, libm, libdl,
# libpthread, librt) or bundled (libscxframework, libsystemc). The other ~16 "missing" libraries are
# GUI only (X11/GTK3/cairo/pango/glib/dbus) and are not needed headless.
LIBATOMIC_DEB="libatomic1_14.2.0-4ubuntu2~24.04.1_arm64.deb"
LIBATOMIC_URL="http://ports.ubuntu.com/ubuntu-ports/pool/main/g/gcc-14/${LIBATOMIC_DEB}"
LIBATOMIC_SHA256="fdeab74e7ad8572cf69c7024e8040c7ac851f6e667d35f0d429e7a0352840f73"
# ⚠ AVAILABILITY, not trust: Ubuntu removes pool packages when superseded. If this 404s, find the
# current libatomic1 in the `noble-updates` Packages index and re-pin — the SHA is checked either
# way, so a substitution fails loudly rather than silently.

# ─── helpers ─────────────────────────────────────────────────────────────────────────────────────

sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }

# Fetch $2 from $1 and check it against $3. Resumes a partial file rather than restarting: the FVP
# is ~91 MB over a link that has already timed out once mid-download, and a resume that corrupts the
# file is caught by the hash on the next line anyway.
fetch_pinned() {
    local url="$1" dest="$2" want="$3" name
    name="$(basename "$dest")"
    if [[ -f "$dest" ]] && [[ "$(sha256 "$dest")" == "$want" ]]; then
        echo "  $name — already present and matches its pin"
        return 0
    fi
    echo "  $name — fetching"
    curl --fail --location --show-error --silent --retry 3 --continue-at - --output "$dest" "$url"
    local got
    got="$(sha256 "$dest")"
    if [[ "$got" != "$want" ]]; then
        echo "FAIL: $name does not match its pinned hash." >&2
        echo "  expected $want" >&2
        echo "  got      $got" >&2
        echo "A resumed download can corrupt; delete '$dest' and re-run before suspecting Arm." >&2
        return 1
    fi
    echo "  $name — hash OK"
}

# ─── go ──────────────────────────────────────────────────────────────────────────────────────────

mkdir -p "$FVP_DIR"
echo "fetch-fvp: populating $FVP_DIR"

fetch_pinned "$FVP_URL"       "$FVP_DIR/$FVP_TARBALL"  "$FVP_SHA256"
fetch_pinned "$UBUNTU_URL"    "$FVP_DIR/$UBUNTU_BASE"  "$UBUNTU_SHA256"
fetch_pinned "$LIBATOMIC_URL" "$FVP_DIR/$LIBATOMIC_DEB" "$LIBATOMIC_SHA256"

# The size check is redundant against the hash and kept anyway: it is the ONLY corroboration the FVP
# pin has, so a future reader can see that the self-attested hash was at least taken from a download
# whose length Arm's CDN independently advertised.
actual_bytes="$(wc -c < "$FVP_DIR/$FVP_TARBALL" | tr -d ' ')"
if [[ "$actual_bytes" != "$FVP_BYTES" ]]; then
    echo "FAIL: FVP tarball is $actual_bytes bytes, expected $FVP_BYTES." >&2
    exit 1
fi

# Extract once. `Base_RevC_AEMvA_pkg/models/Linux64_armv8l_GCC-9.3/` holds the model; `doc/` holds
# the reference guides, which are the RIGHT source for platform facts (§2.8 permits reading them,
# §2.4 forbids the `strings`-the-binary route that would otherwise be tempting).
if [[ ! -d "$FVP_DIR/pkg/Base_RevC_AEMvA_pkg" ]]; then
    echo "  extracting the model package"
    mkdir -p "$FVP_DIR/pkg"
    tar xzf "$FVP_DIR/$FVP_TARBALL" -C "$FVP_DIR/pkg"
fi

MODEL="$(find "$FVP_DIR/pkg" -type f -name 'FVP_Base_RevC-2xAEMvA' -perm -u+x | head -1)"
if [[ -z "$MODEL" ]]; then
    echo "FAIL: extracted the package but found no FVP_Base_RevC-2xAEMvA executable in it." >&2
    exit 1
fi

echo "fetch-fvp: OK"
echo "  model : ${MODEL#"$FVP_DIR"/}"
echo "  docs  : pkg/Base_RevC_AEMvA_pkg/doc/"
echo "  next  : fvp-probe/host/mkinitramfs.sh"
