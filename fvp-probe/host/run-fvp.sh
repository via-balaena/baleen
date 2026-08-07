#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Via Balaena
#
# Build the probe, run it on Arm's model inside the VM, and print the transcript.
#
#   $ fvp-probe/host/run-fvp.sh                 # default: the model's infinite SMMU cache
#   $ fvp-probe/host/run-fvp.sh --cache-on      # minimal cache (size_of_tlb=1) — the other arm
#   $ fvp-probe/host/run-fvp.sh --both          # run both arms and compare. PREFER THIS.
#   $ fvp-probe/host/run-fvp.sh --list-params   # what knobs does this model actually have?
#
# ── ⚠ THE PREMISE THIS FILE WAS WRITTEN ON IS REFUTED. READ THIS BEFORE TRUSTING ANY ARM ─────────
#
# It used to say here that `size_of_tlb` and `size_of_ste_cache` default to ZERO, "i.e. the model
# caches nothing and behaves like QEMU", and that the two arms therefore had to give opposite
# answers. **That is false**, and the model says so itself — every `size_of_*` parameter's
# description ends:
#
#   "If this is zero then it is treated as a large number ('infinite') but it is bounded"
#
# So the default is an INFINITE cache, and the arm that was labelled "caching ON" (at 64 entries)
# made the cache SMALLER than the default. Both arms cached. That is why the first comparison
# produced identical results in both columns — the outcome that sent me to read the descriptions.
#
# ★ **The design principle survives its own premise being wrong, and is the reason this was caught.**
# A witness runnable only in the configuration where it passes is design-lesson #198's failure mode;
# `--both` exists so that reporting one arm is more work than reporting the pair. The comparison
# then falsified its own control before any result was written up. **Run both. Report both.**
#
# The arms now compare cache CAPACITY (infinite vs one entry) rather than presence, because no
# parameter setting appears to disable the cache at all. What the results actually rest on is each
# experiment's INTERNAL control — the post-invalidation step that must show the new mapping.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FVP_DIR="${BALEEN_FVP_DIR:-${REPO_ROOT}/.fvp}"
LINUX_DIR="${BALEEN_LINUX_DIR:-${REPO_ROOT}/.baleen-linux}"
BASE_CPIO="$FVP_DIR/base.cpio.gz"
KERNEL="$LINUX_DIR/Image"

# How long the VM may take before the host gives up. The model runs at ~4.6 MIPS, so a bare-metal
# probe of a few million instructions is seconds; this bound exists to stop a HUNG model from
# holding the terminal, not to bound normal work.
TIMEOUT_SECS="${FVP_TIMEOUT_SECS:-600}"
CYCLELIMIT="${FVP_CYCLELIMIT:-200000000}"

MODE="probe"
CACHE="off"
# Extra `-C name=value` settings, appended verbatim. Exists so a claim ABOUT the model can be tested
# on the model — in particular "an unknown parameter is rejected", which this script's caching arm
# silently depends on and which was asserted here before it was ever checked.
EXTRA_C=()
for arg in "$@"; do
    case "$arg" in
        -C*=*) EXTRA_C+=(-C "${arg#-C}") ; continue ;;
    esac
    case "$arg" in
        --cache-on)     CACHE="on" ;;
        --cache-off)    CACHE="off" ;;
        --both)         MODE="both" ;;
        --list-params)  MODE="list-params" ;;
        # ⚠ These two exist because Arm's BUNDLED documentation does NOT carry the
        # `SMMUv3TestEngine`'s register map — §4.7.36 gives its ports and CADI targets and stops —
        # and Arm's web documentation renders client-side, so it cannot be fetched either. The model
        # is its own most authoritative source about itself, and interrogating it through supported
        # CLI introspection is squarely permitted (§2.8 covers the documentation; §2.4's ban on
        # reverse engineering is why `strings` on the binary is NOT the route taken).
        --list-regs)      MODE="list-regs" ;;
        --list-instances) MODE="list-instances" ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

# ─── the control, run as one command ─────────────────────────────────────────────────────────────
#
# ★ `--both` exists so that reporting a single arm takes MORE effort than reporting the pair.
#
# ⚠ WHAT IT COMPARES CHANGED, AND THE REASON IS A REFUTATION WORTH READING. It was designed as
# caching-OFF vs caching-ON, on the belief that `size_of_tlb=0` disabled the cache. **It does not**
# — every `size_of_*` parameter's own description says "If this is zero then it is treated as a
# large number ('infinite')". The first run of this comparison produced IDENTICAL results in both
# arms, which is what sent me to read the descriptions. **The comparison caught the flaw in itself,
# which is the only reason it was found before the results were written up.**
#
# So the arms are now **infinite cache** (default) vs **minimal cache** (`size_of_tlb=1`), and the
# discriminator is CAPACITY rather than presence: an experiment needing two live entries must behave
# differently when only one fits. A result that is capacity-dependent is caused by caching; one that
# is identical in both arms is not evidence of caching at all.
#
# ⚠ There appears to be NO configuration of this model with the SMMU cache genuinely disabled, so
# a true negative arm is not available by parameter. What stands in for it is each experiment's
# INTERNAL control — the post-invalidation step that must show the new mapping. Those do not depend
# on this comparison and are what the results actually rest on.
if [[ "$MODE" == "both" ]]; then
    off_log="$FVP_DIR/results-infinite-cache.txt"
    on_log="$FVP_DIR/results-minimal-cache.txt"
    echo "run-fvp: arm 1 of 2 — infinite cache (default)"
    "${BASH_SOURCE[0]}" --cache-off > "$off_log" 2>&1 || true
    echo "run-fvp: arm 2 of 2 — minimal cache (size_of_tlb=1)"
    "${BASH_SOURCE[0]}" --cache-on > "$on_log" 2>&1 || true
    echo
    printf '%-16s %-16s %-16s\n' "experiment" "infinite cache" "minimal cache"
    printf '%-16s %-16s %-16s\n' "----------" "--------------" "-------------"
    for name in $(grep -ho 'RESULT [a-z0-9_]*' "$off_log" "$on_log" | awk '{print $2}' | sort -u); do
        o=$(grep -o "RESULT $name=[A-Z]*" "$off_log" | head -1 | cut -d= -f2)
        n=$(grep -o "RESULT $name=[A-Z]*" "$on_log" | head -1 | cut -d= -f2)
        printf '%-16s %-16s %-16s\n' "$name" "${o:-<none>}" "${n:-<none>}"
    done
    echo
    echo "full transcripts: $off_log  /  $on_log"
    exit 0
fi

[[ -f "$BASE_CPIO" ]] || { echo "missing $BASE_CPIO — run fvp-probe/host/mkinitramfs.sh first" >&2; exit 1; }
[[ -f "$KERNEL" ]] || { echo "missing $KERNEL — run hv-metal/linux/fetch-guest-image.sh first" >&2; exit 1; }

# ─── build the probe ─────────────────────────────────────────────────────────────────────────────

if [[ "$MODE" == "probe" ]]; then
    echo "run-fvp: building the probe"
    ( cd "$REPO_ROOT/fvp-probe" && cargo build --release )
    PROBE="$REPO_ROOT/fvp-probe/target/aarch64-unknown-none-softfloat/release/fvp-probe"
    [[ -f "$PROBE" ]] || { echo "build produced no binary at $PROBE" >&2; exit 1; }
fi

# ─── the model's command line ────────────────────────────────────────────────────────────────────
#
# Headless: no visualisation, no telnet terminals (without this the model BLOCKS waiting for a
# telnet client that is never coming), one core per cluster.
#
# ⚠ `bp.pl011_uart0.uart_enable=1` is LOAD-BEARING and is not a QEMU-ism carried over: the Base
# RevC's UART is DISABLED at reset, and the first version of this probe produced total silence
# because of it.
#
# ⚠⚠ `bp.secure_memory=false` IS LOAD-BEARING, AND IT IS A PLATFORM FACT WITH NO QEMU ANALOGUE.
# The Base RevC guards DRAM with a **TZC-400 TrustZone Address Space Controller**, which comes up
# denying access. On a normal boot TF-A's BL1/BL2 programs it before anything else runs; a
# bare-metal image loaded straight into DRAM has no such firmware, and the model says so in as many
# words:
#
#   Error: This image is attempting to run from DRAM, which is access controlled by the TZC-400.
#   Try running firmware beforehand or use parameter bp.secure_memory=false
#
# ★ The model then CONTINUES — it reports `PC=0x8000_0000` and merely warns that "simulation
# performance will be reduced" — so the run looks alive while producing nothing. **Silence again,
# with a plausible-looking transcript above it.** QEMU `virt` has no TZC at all; RAM is RAM. This is
# the third platform assumption in this crate's short life that was invisible until it was measured
# (after the UART's reset state and the IDR0 bit order), which is the argument for the instrument
# rather than an argument against it.
FVP_ARGS=(
    -C bp.secure_memory=false
    -C bp.vis.disable_visualisation=1
    -C bp.terminal_0.start_telnet=0
    -C bp.terminal_1.start_telnet=0
    -C bp.terminal_2.start_telnet=0
    -C bp.terminal_3.start_telnet=0
    -C cluster0.NUM_CORES=1
    -C cluster1.NUM_CORES=1
    -C bp.pl011_uart0.uart_enable=1
    -C bp.pl011_uart0.out_file=/tmp/uart0.log
    -C bp.pl011_uart0.unbuffered_output=1
)

if [[ "$CACHE" == "on" ]]; then
    # ⚠⚠ THE "CACHING OFF" PREMISE THIS FLAG WAS BUILT ON IS **REFUTED**. MEASURED, from the
    # parameters' own descriptions:
    #
    #   "If this is zero then it is treated as a large number ('infinite') but it is bounded"
    #
    # It is on EVERY `size_of_*` cache parameter. So the default of 0 is an **INFINITE** cache, not
    # an absent one — and this arm, at 64, made the TLB SMALLER than the default. Both arms cached,
    # which is exactly why they produced identical results and why that was worth chasing.
    #
    # ★ Kept, renamed in meaning: this is now the **small-cache** arm, and it is still a real
    # control — see `--both`. The parameter NAMES were verified by running the model with a
    # deliberately misspelled one, which it rejects fatally ("parameter not found", run aborts, no
    # UART output). So a silent typo cannot explain a null result here. That check was written down
    # as an assumption before it was ever performed; performing it is what made the rest legible.
    FVP_ARGS+=(
        -C pci.pci_smmuv3.mmu.size_of_tlb=1
        -C pci.pci_smmuv3.mmu.size_of_ste_cache=1
    )
fi

case "$MODE" in
    list-params)    FVP_ARGS+=(--list-params) ;;
    list-regs)      FVP_ARGS+=(--list-regs) ;;
    list-instances) FVP_ARGS+=(--list-instances) ;;
    *)              FVP_ARGS+=(-a /probe.elf --cyclelimit "$CYCLELIMIT" --stat) ;;
esac

# Last, so a caller can override anything set above.
if [[ ${#EXTRA_C[@]} -gt 0 ]]; then
    FVP_ARGS+=("${EXTRA_C[@]}")
fi

# ─── the payload archive ─────────────────────────────────────────────────────────────────────────

PAYLOAD_STAGE="$FVP_DIR/payload"
rm -rf "$PAYLOAD_STAGE"
mkdir -p "$PAYLOAD_STAGE"
cp "$(dirname "${BASH_SOURCE[0]}")/init" "$PAYLOAD_STAGE/init"
chmod +x "$PAYLOAD_STAGE/init"
printf '%s\n' "${FVP_ARGS[*]}" > "$PAYLOAD_STAGE/fvp-args"
# ⚠ An `if`, NOT `[[ cond ]] && cp`. Under `set -e` an AND-list whose test fails returns non-zero at
# top level and kills the script — so the one-liner form would have made `--list-params` exit
# silently right here, in the mode whose entire purpose is to tell us whether the caching parameter
# names are real. A witness-mode that cannot run is worse than no witness mode.
if [[ "$MODE" == "probe" ]]; then
    cp "$PROBE" "$PAYLOAD_STAGE/probe.elf"
fi

( cd "$PAYLOAD_STAGE" && find . -print0 | cpio --null -o -H newc --quiet ) | gzip -1 > "$FVP_DIR/payload.cpio.gz"

# Concatenated gzip streams, unpacked in order by the kernel with later entries winning. A plain
# file concatenation, so this is a 96 MB copy rather than a 300 MB re-archive.
cat "$BASE_CPIO" "$FVP_DIR/payload.cpio.gz" > "$FVP_DIR/combined.cpio.gz"

# ─── run ─────────────────────────────────────────────────────────────────────────────────────────

LOG="$FVP_DIR/vm-console.log"
rm -f "$LOG"
echo "run-fvp: booting the VM (caching $CACHE, mode $MODE, timeout ${TIMEOUT_SECS}s)"

# 6 GB: the model's measured highwater is ~0.735 GB, but the initramfs is unpacked into tmpfs and
# therefore counts against RAM too (~280 MB of model and userspace).
qemu-system-aarch64 \
    -machine virt,accel=hvf -cpu host -smp 4 -m 6144 \
    -kernel "$KERNEL" -initrd "$FVP_DIR/combined.cpio.gz" \
    -append "console=ttyAMA0 panic=1" \
    -nographic -no-reboot > "$LOG" 2>&1 &
QEMU_PID=$!

# macOS ships no `timeout(1)`, so poll. Killing the VM is safe — it holds nothing but a tmpfs.
waited=0
while kill -0 "$QEMU_PID" 2>/dev/null; do
    if [[ "$waited" -ge "$TIMEOUT_SECS" ]]; then
        echo "run-fvp: TIMEOUT after ${TIMEOUT_SECS}s — killing the VM" >&2
        kill -9 "$QEMU_PID" 2>/dev/null || true
        break
    fi
    sleep 2
    waited=$((waited + 2))
done
wait "$QEMU_PID" 2>/dev/null || true

# ─── report ──────────────────────────────────────────────────────────────────────────────────────

if [[ "$MODE" != "probe" ]]; then
    echo "run-fvp: $MODE output written to $LOG ($(wc -l < "$LOG" | tr -d ' ') lines)"
    grep -i "smmu" "$LOG" | head -40 || true
    echo "  (full output: $LOG)"
    exit 0
fi

if ! grep -q "FVP-TRANSCRIPT-BEGIN" "$LOG"; then
    echo "run-fvp: FAIL — the VM never reached the transcript. Last 40 lines of console:" >&2
    tail -40 "$LOG" >&2
    exit 1
fi

echo
echo "──────── FVP transcript (caching $CACHE) ────────"
sed -n '/FVP-TRANSCRIPT-BEGIN/,/FVP-TRANSCRIPT-END/p' "$LOG" | sed '1d;$d'
echo "─────────────────────────────────────────────────"
echo "full console: $LOG"

# A transcript with no probe output at all is a FAILURE, not an empty success — the distinction the
# `!! no /tmp/uart0.log` line inside the VM exists to preserve.
if ! grep -q "FVPPROBE-BEGIN" "$LOG"; then
    echo "run-fvp: FAIL — the model ran but the probe printed nothing." >&2
    exit 1
fi
