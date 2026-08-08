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

# Per-config QEMU additions (see boot_and_check). Empty for the base configs.
EXTRA_QEMU=""
MACHINE_EXTRA=""
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
    # `$EXTRA_QEMU` lets a config add machine options / devices (the SMMU arc needs `iommu=smmuv3`
    # and a real DMA-capable device); it is intentionally word-split and empty for the base configs.
    # shellcheck disable=SC2086
    qemu-system-aarch64 \
        -M "virt,virtualization=on,gic-version=3${MACHINE_EXTRA:-}" \
        -cpu max \
        -nographic \
        -net none \
        $EXTRA_QEMU \
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
    # Forbidden markers — strings that must NEVER appear. The virtio-console negative (M5 Arc 3): the
    # backend refused the descriptor pointing at the un-granted frame, so its SECRET payload must not
    # have reached the console. A mutation that bypassed the grant check would leak it — caught here.
    for m in "${FORBIDDEN_MARKERS[@]}"; do
        if grep -qF "$m" "$out"; then
            echo "boot-test: FAIL ($label) — FORBIDDEN marker '$m' appeared (isolation/grant leak)"
            failed=1
        else
            echo "boot-test: OK ($label) — forbidden '$m' absent"
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

# Strings that must NEVER appear in a boot (checked by boot_and_check on every run). The virtio-console
# negative (M5 Arc 3): the un-granted buffer's SECRET payload the backend refused to read. The virtio-blk
# negatives (M5 Arc 4): tenant 0's write POISON must never cross to the template or to tenant 1's view —
# it appears on the console only if a write reaches the template or two tenants' overlays alias. The cross-vCPU
# vGIC negative (M5 Phase III-3): vCPU B, running with interrupts unmasked while vCPU A holds a pending virtual
# interrupt, must take NONE of it — the XVCPU-LEAK marker prints only if B reads or takes the peer's vINT (a
# list-register leak across the real-scheduler switch), the exact isolation this phase witnesses guest-observed.
FORBIDDEN_MARKERS=(
    "SECRET-ungranted-must-not-appear"
    "POISON-blk-guest0-write-must-not-cross"
    "V4ULTSEC"
    "D3ADTENANT-must-not-survive-rebirth"
    "D3ADSUPER-must-not-survive-rebirth"
    "XVCPU-LEAK-peer-vint-crossed-vcpus"
    # W^X on EL2's own mapping (ledger item 5). The `wx-probe` build stores to EL2's `.text` and the
    # hardware must refuse; this string is printed ONLY if the store was permitted, i.e. the mapping
    # is not read-only. Global rather than per-config on purpose: no configuration may ever reach it.
    "W^X NOT ENFORCED"
    # The X half. Printed only if a jump INTO EL2's data returned, i.e. the fetch was permitted.
    "XN NOT ENFORCED"
)

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
    "superpage OK: the guest round-tripped 0x5079 through a 2 MiB BLOCK descriptor" \
    "isolation negative OK: RO write -> permission fault" \
    "isolation negative OK: foreign-ungranted read -> translation fault" \
    "isolation negative OK: unmapped read -> translation fault" \
    "isolation negative OK: own-page-table read -> translation fault" \
    "NEGATIVE-ISOLATION TEST PASSED" \
    "lifecycle: guest destroyed — dead slot is a clean shell" \
    "lifecycle: reborn slot could NOT link the destroyed grant" \
    "lifecycle positive OK: reborn guest reached its own fresh frame (rw=0xcafe)" \
    "lifecycle negative OK: reborn probe of the destroyed grant -> translation fault" \
    "lifecycle content OK: the reborn slot's re-allocated frame reads as ZERO before it writes" \
    "lifecycle content OK (super): the reborn slot's re-allocated 2 MiB SUPERPAGE reads as ZERO" \
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
    "virtio-console backend: draining" \
    "baleen-guest: hello over a granted virtqueue" \
    "virtio backend REFUSED un-granted access to Mfn 4" \
    "VIRTIO CONSOLE TEST PASSED — granted bytes delivered, un-granted access refused (the ring is a proven grant)" \
    "virtio-blk device identified: magic=\"virt\" version=2 id=2 (block) via trap-and-emulate" \
    "virtio-blk negotiation OK: VIRTIO_F_VERSION_1 accepted, FEATURES_OK set" \
    "virtio-blk READ served sector 0 to tenant 0" \
    "baleen-blk-template-sector-0-pristine" \
    "virtio-blk read round-trip OK: tenant 0 read sector 0 = the pristine template" \
    "virtio-blk WRITE by tenant 0 landed in its CoW overlay" \
    "virtio-blk template-immutability OK: tenant 0's write landed in its CoW overlay; the template is pristine" \
    "virtio backend REFUSED un-granted access to Mfn 5" \
    "virtio-blk read round-trip OK: tenant 1 read sector 0 = the pristine template" \
    "VIRTIO-BLK TEST PASSED — writes hit the CoW overlay, template immutable, peer overlay isolated, un-granted access refused" \
    "vGIC injection OK: guest acknowledged the injected virtual interrupt (INTID 42) via ICC_IAR1_EL1" \
    "VGIC TEST PASSED — a virtual interrupt injected via the list registers reached the guest's CPU interface" \
    "vGIC async-delivery OK: guest TOOK the injected virtual interrupt (INTID 42) at its EL1 IRQ vector" \
    "VGIC ASYNC TEST PASSED — a virtual interrupt was delivered asynchronously to the guest's EL1 vector" \
    "vGIC cross-vCPU isolation OK: vCPU 1 (interrupts unmasked, full vGIC presentation) took none of the peer's pending virtual interrupt (ICC_IAR1_EL1 spurious)" \
    "vGIC cross-vCPU delivery OK: vCPU 0 took its OWN pending virtual interrupt (INTID 42) at its EL1 vector after the peer ran" \
    "VGIC CROSS-VCPU TEST PASSED — a pending virtual interrupt stayed isolated to its vCPU across a real-scheduler switch: the peer (interrupts unmasked) took none, and the owner took exactly its own" \
    "virtual timer OK: CNTVCT advanced" \
    "TIMER TEST PASSED — the guest used the virtual timer (CNTVCT + a programmed deadline) for timekeeping" \
    "PSCI version OK: guest read 0x00010001 (v1.1) — PSCI is discoverable" \
    "PSCI SYSTEM_OFF — the guest powered off (serviced by the hypervisor)" \
    "PSCI TEST PASSED — the guest discovered PSCI (v1.1) and powered off via SYSTEM_OFF" \
    "timer tick OK: the guest took an asynchronous virtual-timer interrupt (INTID 27) at its EL1 vector" \
    "async EL2 timer handler drove hv-core evtchn (raise VIRQ -> deliverable -> inject via the realized fence); the async agent touched GUEST_HV under I1, no halt" \
    "TIMER TICK TEST PASSED — a physical timer interrupt reached EL2 and was delivered to the guest as a virtual interrupt" \
    "thesis non-interference OK: the disposable's probe of the vault secret -> translation fault" \
    "thesis channel enumeration: no grant, no event channel, no shared page-table link, no control edge between vault and disposable" \
    "thesis reborn OK: a reborn disposable could NOT link the vault's secret" \
    "THESIS TEST PASSED — the vault's secret never reached the disposable"

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
    "selftest: BootCell exclusion OK (second borrow refused while live, accepted after drop" \
    "selftest: I1 IRQ-mask check OK (masked DAIF accepted, unmasked rejected, live EL2 context masked)" \
    "selftest: vGIC LR-bank ownership OK" \
    "selftest: vGIC pending-overflow OK" \
    "selftest: Stage-2 encoding verified" \
    "1 super-span 2 MiB block(s) emitted and decoded; device window 0 MiB" \
    "guest HVC serviced: nr=0 arg=100 -> result=100" \
    "guest HVC serviced: nr=1 arg=30 -> result=70" \
    "guest observed HvCall result=70 via HVC round-trip" \
    "isolation positive OK: rw=0xbeef ro=0x5eed fgrant=0xf00d" \
    "superpage OK: the guest round-tripped 0x5079 through a 2 MiB BLOCK descriptor" \
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
    "lifecycle content OK: the reborn slot's re-allocated frame reads as ZERO before it writes" \
    "lifecycle content OK (super): the reborn slot's re-allocated 2 MiB SUPERPAGE reads as ZERO" \
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
    "virtio-console backend: draining" \
    "baleen-guest: hello over a granted virtqueue" \
    "virtio backend REFUSED un-granted access to Mfn 4" \
    "VIRTIO CONSOLE TEST PASSED — granted bytes delivered, un-granted access refused (the ring is a proven grant)" \
    "virtio-blk device identified: magic=\"virt\" version=2 id=2 (block) via trap-and-emulate" \
    "virtio-blk negotiation OK: VIRTIO_F_VERSION_1 accepted, FEATURES_OK set" \
    "virtio-blk READ served sector 0 to tenant 0" \
    "baleen-blk-template-sector-0-pristine" \
    "virtio-blk read round-trip OK: tenant 0 read sector 0 = the pristine template" \
    "virtio-blk WRITE by tenant 0 landed in its CoW overlay" \
    "virtio-blk template-immutability OK: tenant 0's write landed in its CoW overlay; the template is pristine" \
    "virtio backend REFUSED un-granted access to Mfn 5" \
    "virtio-blk read round-trip OK: tenant 1 read sector 0 = the pristine template" \
    "VIRTIO-BLK TEST PASSED — writes hit the CoW overlay, template immutable, peer overlay isolated, un-granted access refused" \
    "vGIC injection OK: guest acknowledged the injected virtual interrupt (INTID 42) via ICC_IAR1_EL1" \
    "VGIC TEST PASSED — a virtual interrupt injected via the list registers reached the guest's CPU interface" \
    "vGIC async-delivery OK: guest TOOK the injected virtual interrupt (INTID 42) at its EL1 IRQ vector" \
    "VGIC ASYNC TEST PASSED — a virtual interrupt was delivered asynchronously to the guest's EL1 vector" \
    "vGIC cross-vCPU isolation OK: vCPU 1 (interrupts unmasked, full vGIC presentation) took none of the peer's pending virtual interrupt (ICC_IAR1_EL1 spurious)" \
    "vGIC cross-vCPU delivery OK: vCPU 0 took its OWN pending virtual interrupt (INTID 42) at its EL1 vector after the peer ran" \
    "VGIC CROSS-VCPU TEST PASSED — a pending virtual interrupt stayed isolated to its vCPU across a real-scheduler switch: the peer (interrupts unmasked) took none, and the owner took exactly its own" \
    "virtual timer OK: CNTVCT advanced" \
    "TIMER TEST PASSED — the guest used the virtual timer (CNTVCT + a programmed deadline) for timekeeping" \
    "PSCI version OK: guest read 0x00010001 (v1.1) — PSCI is discoverable" \
    "PSCI SYSTEM_OFF — the guest powered off (serviced by the hypervisor)" \
    "PSCI TEST PASSED — the guest discovered PSCI (v1.1) and powered off via SYSTEM_OFF" \
    "timer tick OK: the guest took an asynchronous virtual-timer interrupt (INTID 27) at its EL1 vector" \
    "async EL2 timer handler drove hv-core evtchn (raise VIRQ -> deliverable -> inject via the realized fence); the async agent touched GUEST_HV under I1, no halt" \
    "TIMER TICK TEST PASSED — a physical timer interrupt reached EL2 and was delivered to the guest as a virtual interrupt" \
    "thesis non-interference OK: the disposable's probe of the vault secret -> translation fault" \
    "thesis channel enumeration: no grant, no event channel, no shared page-table link, no control edge between vault and disposable" \
    "thesis reborn OK: a reborn disposable could NOT link the vault's secret" \
    "THESIS TEST PASSED — the vault's secret never reached the disposable" \
    "vector=4 (cur_el_spx_sync)" \
    "EC=0x3c"

# ─── SMMU arc, rung 1 — the DMA default-deny witness (two configs, and BOTH are needed) ──────────
#
# Every isolation result above is about CPU accesses. These two boots are baleen's first statement
# about BUS MASTERS, and they only mean something as a pair:
#
#   * "dma-control" — no IOMMU in the machine. A real DMA-capable device (QEMU's `edu`) writes over a
#     sentinel in EL2 RAM and the write MUST LAND. Without this, the deny result below would be
#     vacuous: a sentinel can survive because the SMMU blocked the write, or because the BAR was
#     misassigned / bus mastering never enabled / the device absent (design-lesson #66).
#   * "smmu" — same device, machine with `iommu=smmuv3`, and a binary that sets `SMMU_GBPA.ABORT`
#     BEFORE enabling the device's bus mastering. The same write MUST BE ABORTED.
#
# `dma_mask` is not decoration: `edu` defaults to a 28-bit DMA mask, which cannot reach the metal's
# sentinel (~0x400b1000), so the device silently transfers nothing and the control fails for a reason
# that has nothing to do with the SMMU. Measured the hard way.
EXTRA_QEMU="-device edu,dma_mask=0xffffffffff"
boot_and_check "dma-control" "" \
    "hv-metal alive" \
    "smmu rung1 POSITIVE CONTROL OK"

# Rung 2 runs in the SAME boot as rung 1's deny, and needs no second machine: its phases differ from
# each other only in the contents of one 64-byte Stream Table Entry (or, for the last, in the table
# size announced to the SMMU), which is a far smaller difference than "a machine with an IOMMU vs one
# without". The four markers are four distinct facts, and the FIRST is the load-bearing one:
#
#   * THROUGH-STE POSITIVE CONTROL — the device's own StreamID bound to a bypass STE, DMA LANDS.
#     Without this the deny below is vacuous: a wrong LOG2SIZE, a mis-aligned STRTAB_BASE, a StreamID
#     that is not the device's RequesterID, or an SMMUEN that never took ALL yield "aborted".
#     (Probed: with CR0.SMMUEN never written, every phase reports "aborted" — and this marker is
#     what goes red.)
#   * STREAM-TABLE DEFAULT-DENY — same device, same DMA, STE zeroed (V=0): ABORTED, and the SMMU
#     records C_BAD_STE naming that StreamID on the event queue.
#   * STREAMID-SPECIFIC — a permissive STE one StreamID away does NOT admit this device; re-binding
#     its own StreamID lets the DMA land again, so the denials were decisions and not a wedged SMMU.
#   * OUT-OF-RANGE STREAMID — with the entry still saying BYPASS, announcing a 1-entry table puts the
#     StreamID outside the range: ABORTED with C_BAD_STREAMID. The range check is what makes "size
#     the table to bus 0" a stronger denial than a zeroed entry rather than a coverage gap.
#
# Rung 3 (TRANSLATION) runs in the same boot again, and needs one machine change: `-m 2048`. Its
# control asserts the DMA landed where the TABLE says and NOT at the address the device asked for —
# and the second half is only a check if that address is real memory. The addresses the device issues
# are guest IPAs (`0x8000_0000 +`), which QEMU `virt`'s default 128 MiB does not back; on such a
# machine "the device did not write there" would be true whatever the SMMU did. The metal seeds and
# reads back every observed address before each transfer, so a wrong `-m` fails loudly rather than
# passing vacuously — but the right `-m` is here.
#
#   * TRANSLATION POSITIVE CONTROL — StreamID bound to a domain's OWN Stage-2 tables (S2TTB = the
#     table VTTBR_EL2 carries, S2VMID = the domain's VMID); the device asks for an IPA and the data
#     arrives at a DIFFERENT physical address, the one a walk of the emitted descriptors names.
#   * CONFINEMENT — an IPA the domain does not own: ABORTED, F_TRANSLATION naming that address.
#   * PERMISSION — the read-only leaf hv-s2 emitted refuses the DEVICE's write (F_PERMISSION), so the
#     proven emitter's permission bits govern the device path too.
#   * STREAM-TO-DOMAIN BINDING — the same device, the same IPA, an STE naming the OTHER domain:
#     aborted, and the first domain's memory untouched; that STE then reaches the other domain's own
#     frame, and rebinding reaches the first's again.
#   * RESTORED — unbound, and the table denies every StreamID again.
#
# `-global arm-smmuv3.stage=2` is not decoration either, and it is the difference between this boot
# and the CI runner's. QEMU advertises `SMMU_IDR0.S2P` only when the SMMU device's `stage` property
# says so, and the two ends of the version range disagree about who sets it:
#
#   * QEMU >= 10.0: `virt`'s `create_smmu()` sets `stage = "nested"` itself, so S1P|S2P are both
#     advertised — and because the machine sets it AFTER `qdev_new`, it also OVERRIDES this `-global`,
#     which is why the flag is a harmless no-op there (measured: `stage=1`, `2` and `nested` all give
#     the identical `IDR0 = 0x0d44101b`).
#   * QEMU 8.2 (what `ubuntu-24.04` runners ship): `create_smmu()` sets nothing, the property defaults
#     to stage 1, `IDR0 = 0x0d44101a` — **S2P clear** — and a `Config = 0b110` STE is correctly
#     rejected with `C_BAD_STE`. Nothing overrides `-global` there, so this is what turns it on.
#
# The metal now REQUIRES `IDR0.S2P` before rung 3 runs, so a machine that does not implement stage 2
# fails loudly and by name rather than reporting a wall of unexplained `C_BAD_STE`.
#
# Rung 4b (THE TABLE IS DERIVED) runs in the same boot again and needs no machine change at all —
# which is the point. Rung 3 bound its STE by hand; nothing in rung 4b touches the SMMU. Every entry
# is DERIVED from `hv-core`'s proven device→domain relation by `teardown::dispatch`'s post-dispatch
# funnel, as a consequence of a hypercall issued through the real `Hypervisor::dispatch`, so the
# stream table becomes a REFINEMENT of that relation exactly as the Stage-2 tables are a refinement
# of the `p2m`. The four markers run Arc-0's lifecycle matrix on the DEVICE path:
#
#   * DERIVATION POSITIVE CONTROL — one `HvCall::DeviceAssign` and nothing else; the derived STE
#     names the domain's own VTTBR_EL2 table and VMID, and the DMA lands where the TABLE says (not at
#     the IPA the device issued). First, and stronger than rung 3's control, because it witnesses the
#     derivation as well as the translation.
#   * RELEASE — `HvCall::DeviceRelease` makes the derived table deny EVERY StreamID: aborted with
#     C_BAD_STE. Re-assigning lets the same DMA land again, so the denial was a decision the RELATION
#     made rather than a wedged SMMU (design-lesson #70c).
#   * TEARDOWN — the domain is destroyed while HOLDING the device. Nothing unbinds the stream:
#     `hv-core`'s `release_all_of` takes the assignment and the re-derivation turns that into a
#     denying entry. The same device asking for the same IPA is aborted, and the dead domain's old
#     landing PA is untouched (seeded AFTER the destroy, because the funnel scrubs a freed frame and
#     a sentinel written before the scrub would be zero either way).
#   * REBIRTH — a fresh domain in the same slot re-allocates the SAME model frame at the SAME
#     physical address, and its memory survives intact: the dead tenant's bus master reaches nothing
#     of the reborn tenant's. Re-assigning then lands in the REBORN domain's frame.
#
# **The headline probe:** delete `device::System::release_all_of` from `domain_destroy` and the
# TEARDOWN and REBIRTH markers both go red, with the dead tenant's device writing into the reborn
# tenant's memory. That is the confused deputy in the one flavour every CPU-side proof in this
# repository is structurally blind to — a bus master already pointed at a live tenant's memory,
# writing with no hypercall and no vCPU.
MACHINE_EXTRA=",iommu=smmuv3"
EXTRA_QEMU="-m 2048 -global arm-smmuv3.stage=2 -device edu,dma_mask=0xffffffffff"
boot_and_check "smmu" "--features smmu" \
    "hv-metal alive" \
    "smmu rung1 DEFAULT-DENY OK" \
    "smmu rung2 THROUGH-STE POSITIVE CONTROL OK" \
    "smmu rung2 STREAM-TABLE DEFAULT-DENY OK" \
    "smmu rung2 STREAMID-SPECIFIC OK" \
    "smmu rung2 OUT-OF-RANGE STREAMID OK" \
    "smmu rung3 TRANSLATION POSITIVE CONTROL OK" \
    "smmu rung3 CONFINEMENT OK" \
    "smmu rung3 PERMISSION OK" \
    "smmu rung3 STREAM-TO-DOMAIN BINDING OK" \
    "smmu rung3 RESTORED OK" \
    "smmu rung4 DERIVATION POSITIVE CONTROL OK" \
    "smmu rung4 RELEASE OK" \
    "smmu rung4 TEARDOWN OK" \
    "smmu rung4 REBIRTH OK"
EXTRA_QEMU=""
MACHINE_EXTRA=""

# ── W^X on EL2's own stage-1 mapping (ledger item 5) ───────────────────────────────────────────────
#
# THIS BOOT IS EXPECTED TO END IN A FAULT. The probe stores to EL2's `.text`, which the mapping makes
# read-only; vector 4 reports and halts by design ("we report the fault and halt" — `exceptions.rs`),
# so there is no clean shutdown to assert and the fault report IS the result.
#
# The three required markers below are one claim each, and the FORBIDDEN "W^X NOT ENFORCED" (declared
# globally above) is what makes them mean something: it is printed only if the store was PERMITTED.
#   - "EL2 MMU on"          -> the mapping was installed and `SCTLR_EL2.C` is still 0 (unchanged
#                              attributes), so this is testing permissions and nothing else
#   - "W^X probe: storing"  -> the probe actually ran; without it "no fault" would be vacuous
#   - "EC=0x25"             -> a DATA ABORT FROM THE SAME EL, i.e. EL2 faulted on its own access —
#                              not a guest fault, not an external abort
#
# ★ The negative control needs no build: with the MMU off — every commit before this rung — the same
# store succeeds silently. Removing the fix is what the entire history already did.
boot_and_check "wx-probe" "--features wx-probe" \
    "hv-metal alive" \
    "EL2 MMU on" \
    "W^X probe: storing to EL2 text" \
    "EC=0x25"

# ── The X half of W^X: EL2's own data must not be executable ──────────────────────────────────────
#
# ALSO EXPECTED TO END IN A FAULT, and a DIFFERENT one: an instruction abort (EC=0x21), not the data
# abort (EC=0x25) the `wx-probe` config takes. The two syndromes are what keep the halves from being
# mistaken for one another.
#
# ⚠ ATTRIBUTION, measured rather than assumed: the fault LOOKED over-determined (the page is
# Device-nGnRnE as well as XN, and Arm prohibits instruction fetch from Device memory on its own),
# but a probe that cleared XN while keeping Device found the jump SUCCEEDS. QEMU does not model that
# prohibition, so here XN alone refuses and this witness is sharp. On silicon the property would be
# doubly held and the probe would no longer isolate XN — a fidelity gap, recorded in `mmu::xn_probe`.
#
# The probe self-validates: it reads the descriptor back and refuses to run if its target is not
# actually mapped XN, so "it faulted" cannot come from having jumped somewhere else.
boot_and_check "xn-probe" "--features xn-probe" \
    "hv-metal alive" \
    "EL2 MMU on" \
    "XN probe: jumping into EL2 data" \
    "EC=0x21"

echo "boot-test: OK — all checks passed"
