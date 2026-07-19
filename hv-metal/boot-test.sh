#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Via Balaena
#
# Headless QEMU boot smoke-test. Build hv-metal for the bare-metal target, boot it on the QEMU
# `virt` machine at EL2, and assert the expected serial markers appear. This is the metal side of
# the "diamond -> CI-green -> merge" loop; CI runs it (see .github/workflows/ci.yml) and so can you.
#
# The boot runs TWICE (through M4 Arc 4):
#   - the DEFAULT build: at EL2, vectors installed, HCR_EL2.RW=1, the generic-timer TimeSource live
#     and monotonic, a synthetic HvCall dispatched directly into the linked hv-core brain (Arc 3),
#     and then the Arc-4 headline — a real EL1 guest issues HVC, traps to EL2, and has both
#     hypercalls serviced through the ACTUAL Hypervisor::dispatch (nr=0 arg=100 -> 100, nr=1 arg=30
#     -> 70), with the guest observing the serviced balance on a round-trip HVC (asserts each);
#   - the `--features selftest` build: additionally asserts the Arc-3 accounting witness
#     (grant 100 / spend 30 -> balance 70), hard-asserts the guest round-trip equality, then — chained
#     at the end of the guest report — deliberately executes `BRK #0` so the installed exception
#     vectors must CATCH and DECODE the fault (asserts the class `EC=0x3c` and the slot `vector=4`).
#     Each marker is a witness produced BY the mechanism under test (design-lessons #23, #24(f)).
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

# Default path: the whole Arc-3 sequence must complete. Each marker guards a distinct mechanism, so
# a regression in any one is caught even without the self-test:
#   - VBAR_EL2 installed          -> VBAR_EL2 read back == the vector-table address (Arc 2); the
#                                    marker is printed ONLY when the read-back confirms the write took
#                                    (the selftest BRK below is the complementary end-to-end check);
#   - HCR_EL2.RW=1                 -> HCR_EL2 was configured and read back correct;
#   - generic timer live          -> the TimeSource read a monotonic, advancing count;
#   - HvCall CreditGrant ... =100  -> the linked hv-core brain serviced a real hypercall on the metal
#                                    (printed ONLY when the dispatch returned exactly Balance(100)).
#
# Arc-4 review note on which of the guest markers are genuine WITNESSES vs. progress lines:
#   - "entering EL1 guest" is a PROGRESS line, printed before the `eret` — it does NOT itself prove
#     entry (an unconditional print, like the Arc-3 "VBAR_EL2 installed" false-green PR#32 fixed). The
#     actual proof of EL1 entry is the pair of "guest HVC serviced ..." lines below: those print only
#     when the guest ran, trapped, and the real Hypervisor::dispatch returned — a broken eret/Stage-2
#     yields none of them and this test FAILS.
#   - the "-> result=100" / "-> result=70" VALUES are load-bearing: the marker line is an
#     unconditional print, but its integrity rests on the fixed result value here (grep -F). Do NOT
#     loosen these to a value-free substring (e.g. "guest HVC serviced: nr=0") — that would let a
#     rejected/stubbed call (result=u64::MAX) pass. The value is the witness.
#   - "guest observed HvCall result=70 via HVC round-trip" prints ONLY on an exact echoed==served==70
#     match — genuine proof the guest observed the serviced balance (70 is no call's input).
boot_and_check "default" "" \
    "hv-metal alive" \
    "CurrentEL = EL2" \
    "VBAR_EL2 installed" \
    "HCR_EL2.RW=1" \
    "generic timer live" \
    "HvCall CreditGrant(100) -> balance=100" \
    "entering EL1 guest" \
    "guest HVC serviced: nr=0 arg=100 -> result=100" \
    "guest HVC serviced: nr=1 arg=30 -> result=70" \
    "guest observed HvCall result=70 via HVC round-trip"

# Self-test path: additionally, the HvCall accounting witness (printed ONLY when grant 100 / spend 30
# both returned the exact expected balances — a witness produced by the dispatch itself), then the
# deliberate BRK must be caught and decoded. We assert BOTH the decoded class (EC=0x3c, from
# ESR_EL2) AND the vector slot that fired (vector=4 (cur_el_spx_sync), from the table stub's
# `mov w0,#N`) — the latter binds the runtime check to the 16-entry slot-index plumbing, which the
# ESR-derived EC alone does not exercise.
boot_and_check "selftest" "--features selftest" \
    "hv-metal alive" \
    "CurrentEL = EL2" \
    "VBAR_EL2 installed" \
    "HCR_EL2.RW=1" \
    "generic timer live" \
    "HvCall CreditGrant(100) -> balance=100" \
    "selftest: HvCall accounting OK" \
    "guest HVC serviced: nr=0 arg=100 -> result=100" \
    "guest HVC serviced: nr=1 arg=30 -> result=70" \
    "guest observed HvCall result=70 via HVC round-trip" \
    "selftest: guest round-trip OK" \
    "vector=4 (cur_el_spx_sync)" \
    "EC=0x3c"

echo "boot-test: OK — all checks passed"
