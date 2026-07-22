#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Via Balaena
#
# Headless QEMU boot smoke-test. Build hv-metal for the bare-metal target, boot it on the QEMU
# `virt` machine at EL2, and assert the expected serial markers appear. This is the metal side of
# the "diamond -> CI-green -> merge" loop; CI runs it (see .github/workflows/ci.yml) and so can you.
#
# The boot runs TWICE (through M5 Arc 1). After the isolation matrix and the lifecycle phase, the
# M5 Arc 1 SCHEDULER phase runs: two vCPUs of one domain time-slice on the single physical CPU,
# switched by hv-core's real scheduler (SchedPreempt + SchedRun on each cooperative yield), each
# carrying a private counter that survives the interleaving; plus two sched-pillar refusals —
# SchedRun onto the occupied pCPU (PcpuBusy, exclusivity) and onto a non-affine pCPU (NotAffine).
# The SCHEDULER TEST PASSED marker prints only when both vCPUs' contexts round-tripped intact.
# The details of the earlier phases:
#   - the DEFAULT build: at EL2, vectors installed, HCR_EL2.RW=1, the generic-timer TimeSource live
#     and monotonic, a synthetic HvCall dispatched directly into the linked hv-core brain (Arc 3),
#     the Arc-4 trap-and-service round trip (nr=0 arg=100 -> 100, nr=1 arg=30 -> 70, guest echoes 70),
#     then the Arc-5 NEGATIVE-ISOLATION TEST: the guest runs behind REAL AArch64 Stage-2 tables
#     generated from the proven p2m, its authorized accesses SUCCEED (rw=0xbeef, ro=0x5eed seeded by
#     the HV through GuestMemory, fgrant=0xf00d) and its unauthorized accesses are FAULTED by the
#     hardware — a write to a read-only frame -> permission fault, a read of an un-granted peer frame
#     and of an unmapped IPA -> translation faults — each decoded (EC=0x24) and confirmed against the
#     model. The matrix PASSED marker prints only when every dimension holds. THEN the M5 Arc 0
#     LIFECYCLE phase: dom0 DESTROYS the guest (the proven teardown — the dead slot is Dead and owns
#     no frames), REBORNS a fresh domain in the SAME slot, and witnesses that it inherits nothing —
#     the reborn slot cannot even LINK the frame the peer had granted to the dead guest (the grant was
#     swept), so its probe of that frame is FAULTED by the hardware (translation, DFSC=0x07). The
#     LIFECYCLE PASSED marker prints only when the reborn guest reaches its own fresh frame AND is
#     denied the inherited one — the confused-deputy defense (design-lesson #15), live on the metal;
#   - the `--features selftest` build: additionally asserts the Arc-3 accounting witness
#     (grant 100 / spend 30 -> balance 70), hard-asserts the isolation matrix, then — chained at the
#     end of the final report — deliberately executes `BRK #0` so the installed exception vectors must
#     CATCH and DECODE the fault (asserts the class `EC=0x3c` and the slot `vector=4`).
#     Each marker is a witness produced BY the mechanism under test (design-lessons #23, #24(f), #25).
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
# Note on which of the guest markers are genuine WITNESSES vs. progress lines:
#   - "entering EL1 guest" is a PROGRESS line, printed before the `eret` — it does NOT itself prove
#     entry (an unconditional print, like the Arc-3 "VBAR_EL2 installed" false-green PR#32 fixed). The
#     actual proof of EL1 entry is the "guest HVC serviced ..." lines below and the isolation markers:
#     those print only when the guest ran, trapped, and was serviced/faulted — a broken eret/Stage-2
#     yields none of them and this test FAILS.
#   - the "-> result=100" / "-> result=70" VALUES are load-bearing: do NOT loosen to a value-free
#     substring — that would let a rejected/stubbed call (result=u64::MAX) pass. The value is the
#     witness. Likewise the Arc-5 isolation lines carry load-bearing content:
#   - "isolation positive OK: rw=0xbeef ro=0x5eed fgrant=0xf00d" prints ONLY when every authorized
#     access succeeded AND the hypervisor read the guest's writes back through GuestMemory. ro=0x5eed
#     is un-forgeable: the guest never holds that immediate — it can only echo it by READING the frame
#     the hypervisor seeded, so it proves the read-only Stage-2 mapping resolves to the right machine
#     frame. Keep the values (grep -F).
#   - each "isolation negative OK: ... -> permission/translation fault" line prints ONLY when the
#     decoded fault (EC=0x24 data abort, ESR.DFSC class, WnR) matches the expected denial — a witness
#     produced BY the real Stage-2 tables faulting the access. "permission fault" vs "translation
#     fault" is load-bearing (it distinguishes S2AP-denied-write from unmapped-IPA).
#   - "own-page-table read -> translation fault" is the write-xor-pagetable case: G's frame typed as
#     a page table is not a leaf, so it is unmapped and unreachable as data — the headline p2m
#     invariant, enforced by real hardware.
#   - "NEGATIVE-ISOLATION TEST PASSED" prints ONLY when the whole authorize/deny matrix holds — the
#     positive controls succeeded and all four denials faulted with the right class, and the
#     authorized frames did NOT fault. This is the diamond: deny exactly what the model forbids.
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
    "guest observed HvCall result=70 via HVC round-trip" \
    "isolation positive OK: rw=0xbeef ro=0x5eed fgrant=0xf00d" \
    "isolation negative OK: RO write -> permission fault" \
    "isolation negative OK: foreign-ungranted read -> translation fault" \
    "isolation negative OK: unmapped read -> translation fault" \
    "isolation negative OK: own-page-table read -> translation fault" \
    "NEGATIVE-ISOLATION TEST PASSED" \
    "lifecycle: guest destroyed — dead slot is a clean shell" \
    "lifecycle: reborn slot could NOT link the destroyed grant" \
    "lifecycle positive OK: reborn guest reached its own fresh frame (rw=0xcafe)" \
    "lifecycle negative OK: reborn probe of the destroyed grant -> translation fault" \
    "LIFECYCLE ISOLATION TEST PASSED" \
    "scheduler exclusivity OK: SchedRun onto the occupied pCPU refused (PcpuBusy)" \
    "scheduler affinity OK: SchedRun onto a non-affine (free) pCPU refused (NotAffine)" \
    "SCHEDULER TEST PASSED — two vCPUs time-sliced, each context preserved" \
    "cross-domain exclusivity OK: dom B SchedRun onto dom A's pCPU refused (PcpuBusy)" \
    "concurrent no-corruption OK: each domain kept its own frame after the peer ran" \
    "concurrent isolation OK: dom A probing dom B's frame -> translation fault" \
    "concurrent isolation OK: dom B probing dom A's frame -> translation fault" \
    "CONCURRENT ISOLATION TEST PASSED — two domains (VMID 1/2) time-sliced in distinct Stage-2, each faulted on the peer's memory, no cross-corruption, no tlbi on switch" \
    "virtio-mmio device identified: magic=\"virt\" version=2 id=3 (console) via trap-and-emulate" \
    "virtio negotiation OK: VIRTIO_F_VERSION_1 accepted, FEATURES_OK set" \
    "VIRTIO CONSOLE TEST PASSED — virtio-mmio device identified + VERSION_1 negotiated"

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
    "isolation positive OK: rw=0xbeef ro=0x5eed fgrant=0xf00d" \
    "isolation negative OK: RO write -> permission fault" \
    "isolation negative OK: foreign-ungranted read -> translation fault" \
    "isolation negative OK: unmapped read -> translation fault" \
    "isolation negative OK: own-page-table read -> translation fault" \
    "NEGATIVE-ISOLATION TEST PASSED" \
    "selftest: isolation matrix OK" \
    "lifecycle: guest destroyed — dead slot is a clean shell" \
    "lifecycle: reborn slot could NOT link the destroyed grant" \
    "lifecycle positive OK: reborn guest reached its own fresh frame (rw=0xcafe)" \
    "lifecycle negative OK: reborn probe of the destroyed grant -> translation fault" \
    "LIFECYCLE ISOLATION TEST PASSED" \
    "scheduler exclusivity OK: SchedRun onto the occupied pCPU refused (PcpuBusy)" \
    "scheduler affinity OK: SchedRun onto a non-affine (free) pCPU refused (NotAffine)" \
    "SCHEDULER TEST PASSED — two vCPUs time-sliced, each context preserved" \
    "cross-domain exclusivity OK: dom B SchedRun onto dom A's pCPU refused (PcpuBusy)" \
    "concurrent no-corruption OK: each domain kept its own frame after the peer ran" \
    "concurrent isolation OK: dom A probing dom B's frame -> translation fault" \
    "concurrent isolation OK: dom B probing dom A's frame -> translation fault" \
    "CONCURRENT ISOLATION TEST PASSED — two domains (VMID 1/2) time-sliced in distinct Stage-2, each faulted on the peer's memory, no cross-corruption, no tlbi on switch" \
    "virtio-mmio device identified: magic=\"virt\" version=2 id=3 (console) via trap-and-emulate" \
    "virtio negotiation OK: VIRTIO_F_VERSION_1 accepted, FEATURES_OK set" \
    "VIRTIO CONSOLE TEST PASSED — virtio-mmio device identified + VERSION_1 negotiated" \
    "vector=4 (cur_el_spx_sync)" \
    "EC=0x3c"

echo "boot-test: OK — all checks passed"
