#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Via Balaena
#
# **Decide whether this PR (or push) touches proof-relevant code.**
#
# Writes `run=true` or `run=false` to `$GITHUB_OUTPUT`, which gates the heavy steps in
# `proofs.yml`'s `kani proofs (PR)` and `verus proofs (PR)` — the two REQUIRED contexts standing in
# front of 136 Kani harnesses and 117 Verus obligations. **This is the highest-leverage checker in
# the repository: it decides whether the proof corpus runs at all.** A false `run=false` lets a
# proof-breaking PR merge green, which is the exact failure ① (#76) made these gates required to
# prevent, and which the 2026-07-26 adversarial review called its #1 material finding.
#
# ## FAIL-SAFE by construction, and ㉓ made that testable rather than asserted
#
# Any uncertainty — a missing or all-zero base sha, an unresolvable commit, a failed diff, **a
# `grep` that errors** — resolves to `run=true`. Running a proof unnecessarily costs ~17 minutes;
# skipping one that should have run costs correctness.
#
# ⚠⚠ **㉓ — THE `grep` CASE WAS A REAL HOLE, and it contradicted the paragraph above.** The test
# used to be `if echo "$changed" | grep -qE "$PROOF_PATHS"; then run=true; else run=false; fi`.
# `grep` returns **2 on error** (a malformed regex is the reachable one) and **1 on no-match**, and
# an `if`/`else` cannot tell them apart — so a broken `PROOF_PATHS` resolved to **skip the proofs**,
# the one direction the design says is impossible. ★ And it was self-concealing: this path set
# contains the gate's own files, so editing them normally pays the gate — but a PR that *broke* the
# regex would have `grep` error out and skip, i.e. the gate that would catch the breakage is the one
# the breakage disables. Reachable rather than theoretical: `PROOF_PATHS` is an edited line, and its
# own comment records two recent additions (`hv-vdev` ⑯, `hv-part` ㉒).
#
# ## Why this is a script and not a `run: |` block
#
# Shell buried in YAML cannot be tested. `detect-proof-changes-test.sh` next to this file drives
# every fail-safe above against a hermetic temporary git repository — including the malformed-regex
# case, which is why `PROOF_PATHS` is overridable below. Same pattern the rest of the repo uses:
# `boot-test.sh` and `cargo xtask metal-lint` are the entry points CI *calls*, so the thing a
# developer runs and the thing CI runs are one artifact.
#
# ## Usage
#
#   EVENT=pull_request PR_BASE=<sha> PR_HEAD=<sha> GITHUB_OUTPUT=<file> detect-proof-changes.sh
#   EVENT=push        PUSH_BASE=<sha> PUSH_HEAD=<sha> GITHUB_OUTPUT=<file> detect-proof-changes.sh
#
# Exits 0 ALWAYS. `proofs.yml`'s `changes` job must never fail, or the `needs:`-dependent proof jobs
# cascade into `skipped` — and a skipped required check never reports, which branch protection
# treats as satisfied. Failing safe means *running* the proofs, never failing the decision.

set -uo pipefail

# Proof-relevant closure (confirmed from the manifests): hv-verify -> hv-core + hv-s2,
# hv-core -> hv-hal. Plus the workspace manifest, this gate's workflow, and **this script and its
# test** — ㉓ added the last two, and forgetting them would have been the refactor quietly
# undoing the property that editing the gate pays the gate.
#
# Kept deliberately BROAD — including a path that a given proof does not read only ever runs that
# proof unnecessarily; it can never cause a false skip.
#
# `hv-vdev` (⑯) is listed AHEAD of `hv-verify` depending on it. That is the safe direction and the
# deliberate one: while the harnesses are still being added, a PR touching only the device models
# runs the gate for nothing, which costs ~16 min. The alternative — adding the path in the same
# commit as the dependency — risks the one failure mode this filter must never have, a device-model
# change that green-skips the gate that exists to check it.
#
# `hv-part` (㉒) is added in the SAME commit as its harnesses, which is the direction the note above
# warns about — so state why it is safe here: the crate is created by that commit, so there is no
# window in which a `hv-part` change could have green-skipped a gate that already existed. The
# hazard that note describes is a path added LATER than the code it guards; this is the opposite
# order.
#
# ⚠ Overridable ONLY so the test can inject a malformed pattern. CI never sets it.
PROOF_PATHS="${PROOF_PATHS:-^(hv-hal|hv-core|hv-part|hv-s2|hv-vdev|hv-verify)/|^Cargo\.toml\$|^\.github/workflows/proofs\.yml\$|^\.github/scripts/detect-proof-changes(-test)?\.sh\$}"
ZERO='0000000000000000000000000000000000000000'

EVENT="${EVENT:-}"
if [ "$EVENT" = "pull_request" ]; then
  base="${PR_BASE:-}"; head="${PR_HEAD:-}"
else
  base="${PUSH_BASE:-}"; head="${PUSH_HEAD:-}"
fi

run_true() { echo "$1"; echo "run=true" >> "$GITHUB_OUTPUT"; exit 0; }

# Fail-safe: an unresolvable base (new branch's first push -> all-zero `before`, a force-push, a
# shallow gap) means "diff unavailable" -> run the proofs.
if [ -z "$base" ] || [ "$base" = "$ZERO" ]; then
  run_true "base sha unavailable ($base) — running proofs (fail-safe)"
fi
if ! git cat-file -e "${base}^{commit}" 2>/dev/null; then
  run_true "base commit $base not in history — running proofs (fail-safe)"
fi

changed="$(git diff --name-only "$base" "$head" 2>/dev/null)" \
  || run_true "git diff failed — running proofs (fail-safe)"

echo "changed files:"
echo "$changed"

# ★ ㉓ — the match is read as an EXIT CODE, not as a truth value. `grep` distinguishes three
# outcomes and the two failure ones must go opposite ways: 1 (no match) is the whole point of the
# skip, while 2-or-more (a broken pattern, an I/O error) is uncertainty and must run the proofs.
echo "$changed" | grep -qE "$PROOF_PATHS"
rc=$?
case "$rc" in
  0)
    echo "proof-relevant paths changed — proofs will run"
    echo "run=true" >> "$GITHUB_OUTPUT"
    ;;
  1)
    echo "no proof-relevant paths changed — proofs skip (green)"
    echo "run=false" >> "$GITHUB_OUTPUT"
    ;;
  *)
    run_true "grep failed (exit $rc) — PROOF_PATHS may be malformed — running proofs (fail-safe)"
    ;;
esac
