#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Via Balaena
#
# Headless QEMU boot smoke-test. Build hv-metal for the bare-metal target, boot it on the QEMU
# `virt` machine at EL2, and assert the expected serial markers appear. This is the metal side of
# the "diamond -> CI-green -> merge" loop; CI runs it (see .github/workflows/ci.yml) and so can you.
#
# Arc 2 runs it TWICE:
#   - the DEFAULT build: vectors installed, boots to park at EL2 (asserts the alive marker + that we
#     are actually at EL2);
#   - the `--features selftest` build: deliberately executes `BRK #0`, so the installed exception
#     vectors must CATCH and DECODE the fault (asserts, additionally, the decoded exception class
#     `EC=0x3c`). This is the non-vacuity proof that the vectors fire — design-lesson #23.
#
# Portable timeout: qemu parks in a wfe loop (it never exits on its own), so we run it in the
# background, poll the serial log for the markers, and kill it as soon as they all appear (or once
# we hit the wait cap) — no dependency on `timeout`/`gtimeout`.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
target="aarch64-unknown-none-softfloat"
wait_secs="${BOOT_TEST_WAIT:-8}"

# boot_and_check <label> <cargo-feature-args> <marker>...
# Build hv-metal (with the given feature args), boot it under QEMU, and require every <marker> to
# appear in the serial output. Exits non-zero (dumping the serial log) if any marker is missing.
boot_and_check() {
    local label="$1"; shift
    local features="$1"; shift # may be empty; unquoted on the cargo line so "" expands to nothing

    echo "boot-test: building hv-metal ($label)…"
    # shellcheck disable=SC2086 # $features is intentionally word-split (empty -> no extra args)
    cargo build --release --target "$target" --manifest-path "$here/Cargo.toml" $features
    local bin="$here/target/$target/release/hv-metal"

    echo "boot-test: booting ($label) under qemu-system-aarch64…"
    # `-net none`: the default virt NIC pulls a PXE romfile (efi-virtio.rom) some QEMU packages
    # don't ship (fatal on such builds); we need no networking, so disable it for a deterministic
    # boot.
    local out
    out="$(mktemp)"
    qemu-system-aarch64 \
        -M virt,virtualization=on \
        -cpu max \
        -nographic \
        -net none \
        -kernel "$bin" \
        >"$out" 2>&1 &
    local qemu_pid=$!

    # Poll until every marker is present or we hit the deadline (a green run finishes fast — the
    # markers print in the first moments of boot — while still tolerating a slow/cold runner).
    # Markers are matched as FIXED strings (`grep -F`), not regexes — several contain characters
    # that are regex metacharacters (e.g. the parens in "vector=4 (cur_el_spx_sync)").
    local deadline=$((SECONDS + wait_secs))
    while [ "$SECONDS" -lt "$deadline" ]; do
        local all=1
        for m in "$@"; do
            grep -qF "$m" "$out" || all=0
        done
        [ "$all" -eq 1 ] && break
        sleep 0.25
    done
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true

    local failed=0
    for m in "$@"; do
        if grep -qF "$m" "$out"; then
            echo "boot-test: OK ($label) — found '$m'"
        else
            echo "boot-test: FAIL ($label) — marker '$m' not found"
            failed=1
        fi
    done
    if [ "$failed" -ne 0 ]; then
        echo "----------------------------------------"
        cat "$out"
        echo "----------------------------------------"
        exit 1
    fi
    rm -f "$out"
}

# Default path: at EL2, and the vectors get installed (assert the post-install banner, so a
# regression turning install_vectors into a silent no-op is caught even without firing a fault).
boot_and_check "default" "" \
    "hv-metal alive" \
    "CurrentEL = EL2" \
    "VBAR_EL2 installed"

# Self-test path: the deliberate BRK must be caught and decoded. We assert BOTH the decoded class
# (EC=0x3c, from ESR_EL2) AND the vector slot that fired (vector=4 (cur_el_spx_sync), from the
# table stub's `mov w0,#N`) — the latter binds the runtime check to the 16-entry slot-index
# plumbing, which the ESR-derived EC alone does not exercise.
boot_and_check "selftest" "--features selftest" \
    "hv-metal alive" \
    "CurrentEL = EL2" \
    "VBAR_EL2 installed" \
    "vector=4 (cur_el_spx_sync)" \
    "EC=0x3c"

echo "boot-test: OK — all checks passed"
