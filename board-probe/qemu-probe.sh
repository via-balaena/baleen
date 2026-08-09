#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Via Balaena
#
# **Run `board-probe` on QEMU `virt` — the self-test, and it is not optional.**
#
# The probe's whole purpose is to report facts about a platform nobody has measured. That is only
# worth anything if the instrument is known to work, and the only way to know is to run it where the
# answers are already established. Every VERDICT below should read MATCH on QEMU; anything else means
# the probe is wrong, not the platform.
#
# ⚠ This is `fvp-probe`'s discipline restated (design-lesson #211 / #215): build the control so it
# can falsify itself, and ask what a checker prints when there is nothing to check.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# ⚠ `cd` rather than `--manifest-path`: cargo discovers `.cargo/config.toml` — which is what selects
# the bare-metal TARGET and the linker script — from the WORKING DIRECTORY, not from the manifest.
# Building with `--manifest-path` from elsewhere silently produces a host binary, and the first
# symptom is the boot assembly failing to assemble. Same fact `cargo xtask fvp-lint` records.
cd "$here"
cargo build --release
bin="$here/target/aarch64-unknown-none-softfloat/release/board-probe"

out="$(mktemp)"
qemu-system-aarch64 -M virt,virtualization=on,gic-version=3 -cpu max -nographic -net none \
    -kernel "$bin" >"$out" 2>&1 &
pid=$!
deadline=$((SECONDS + 10))
while [ "$SECONDS" -lt "$deadline" ]; do
    grep -q "BOARD-PROBE-END" "$out" && break
    sleep 0.25
done
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

grep '^@@' "$out" || { echo "qemu-probe: NO TRANSCRIPT — the probe produced nothing"; cat "$out"; exit 1; }

if ! grep -q "BOARD-PROBE-END" "$out"; then
    echo "qemu-probe: FAIL — began but never finished; a register read probably trapped"
    exit 1
fi
# ⚠ Match on VERDICT lines only. The first version grepped for the bare words and counted a NOTE
# line that contained "DIFFERS" while explaining what DIFFERS would mean — a checker miscounting
# because its pattern matched its own prose.
differs="$(grep -c '^@@ VERDICT .*DIFFERS' "$out" || true)"
absent="$(grep -c '^@@ VERDICT .*ABSENT' "$out" || true)"
toosmall="$(grep -c '^@@ VERDICT .*TOO SMALL' "$out" || true)"
echo
if [ "$differs" -eq 0 ] && [ "$absent" -eq 0 ] && [ "$toosmall" -eq 0 ]; then
    echo "qemu-probe: OK — every verdict MATCHes on the platform hv-metal was written against."
    echo "            The instrument agrees with the known answers, so its answers elsewhere mean something."
else
    echo "qemu-probe: ⚠ $differs DIFFERS, $absent ABSENT, $toosmall TOO SMALL on QEMU."
    echo "            On THIS platform that indicts the PROBE, not the platform — hv-metal's"
    echo "            assumptions were measured here. Fix the probe before trusting it on a board."
    exit 1
fi
rm -f "$out"
