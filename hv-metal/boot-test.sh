#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Via Balaena
#
# Headless QEMU boot smoke-test (Arc 0): build hv-metal for the bare-metal target, boot it on the
# QEMU `virt` machine, and assert the serial marker `rust_main` prints. This is the metal side of
# the "diamond -> CI-green -> merge" loop; CI runs it (see .github/workflows/ci.yml) and so can you.
#
# Portable timeout: qemu parks in a wfe loop (it never exits on its own), so we run it in the
# background, poll the serial log for the banner, and kill it as soon as the banner appears (or
# once we hit the wait cap) — no dependency on `timeout`/`gtimeout`.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
target="aarch64-unknown-none-softfloat"
marker="hv-metal alive"
wait_secs="${BOOT_TEST_WAIT:-8}"

echo "boot-test: building hv-metal ($target)…"
cargo build --release --target "$target" --manifest-path "$here/Cargo.toml"
bin="$here/target/$target/release/hv-metal"

echo "boot-test: booting under qemu-system-aarch64…"
# `-net none`: the default virt NIC pulls a PXE romfile (efi-virtio.rom) some QEMU packages don't
# ship (fatal on such builds); Arc 0 needs no networking, so disable it for a deterministic boot.
out="$(mktemp)"
qemu-system-aarch64 \
    -M virt,virtualization=on \
    -cpu max \
    -nographic \
    -net none \
    -kernel "$bin" \
    >"$out" 2>&1 &
qemu_pid=$!

# Poll for the marker instead of a fixed sleep: exit as soon as it appears (the banner prints in
# the first moments of boot, so a green run finishes fast) while still tolerating a slow/cold
# runner up to $wait_secs before giving up.
deadline=$((SECONDS + wait_secs))
found=0
while [ "$SECONDS" -lt "$deadline" ]; do
    if grep -q "$marker" "$out"; then
        found=1
        break
    fi
    sleep 0.25
done
kill "$qemu_pid" 2>/dev/null || true
wait "$qemu_pid" 2>/dev/null || true

# Re-check once after the kill in case the marker landed between the last poll and now.
if [ "$found" -eq 1 ] || grep -q "$marker" "$out"; then
    echo "boot-test: OK — found '$marker'"
    exit 0
else
    echo "boot-test: FAIL — marker '$marker' not found in serial output:"
    echo "----------------------------------------"
    cat "$out"
    echo "----------------------------------------"
    exit 1
fi
