#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR MIT
# Copyright (c) 2026 Via Balaena
#
# **Drive `detect-proof-changes.sh` through every way it can be uncertain, and require each one to
# run the proofs.** Invoked by `cargo xtask ci`, i.e. inside the REQUIRED `fmt · clippy · test`
# context — a test of a gate that lives in a non-required job is advisory, and this rung is about
# gates that actually gate.
#
# ## ★★ The NEGATIVE control is the point, not a formality
#
# Six of the seven cases below assert `run=true`. **A script whose first line is `run=true` passes
# all six.** The skip is the entire reason the gate is affordable — 11 s versus ~17 min — so a suite
# that only tests fail-safes would happily certify a script that had lost the ability to skip, and
# every PR in the repo would silently start paying the Kani gate. Case 7 is what makes the other six
# mean anything (design-lesson #211: build the control so it can falsify itself).
#
# ## Hermetic
#
# Every case runs against a temporary git repository built here, never against baleen's own history:
# a test that pins real commits is a test that rots the moment they scroll away, and one that reads
# the working tree would pass or fail on what the developer happens to have staged.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
script="$here/detect-proof-changes.sh"
failed=0

# check <case-name> <expected-run> <env assignments...>
# Runs the script with a fresh $GITHUB_OUTPUT and asserts the `run=` it wrote.
check() {
  local name="$1" expect="$2"; shift 2
  local out; out="$(mktemp)"
  local log; log="$(mktemp)"
  # `env -i` is deliberately NOT used: the script needs PATH and git's environment. The variables
  # under test are passed explicitly, and the script defaults every one it reads.
  if ! GITHUB_OUTPUT="$out" "$@" bash "$script" >"$log" 2>&1; then
    echo "FAIL ($name) — the script exited non-zero; it must ALWAYS exit 0, or the proof jobs"
    echo "                cascade into a skipped (and thus never-reporting) required check"
    sed 's/^/    /' "$log"
    failed=1
    rm -f "$out" "$log"
    return
  fi
  local got; got="$(grep -o 'run=[a-z]*' "$out" | tail -1)"
  if [ "$got" = "run=$expect" ]; then
    echo "OK   ($name) — $got"
  else
    echo "FAIL ($name) — expected run=$expect, got '${got:-<nothing written>}'"
    sed 's/^/    /' "$log"
    failed=1
  fi
  rm -f "$out" "$log"
}

# ── A hermetic repo: one commit touching a proof path, one touching only docs. ──────────────────
repo="$(mktemp -d)"
trap 'rm -rf "$repo"' EXIT
(
  cd "$repo" || exit 1
  git init -q .
  git config user.email t@example.invalid
  git config user.name t
  mkdir -p hv-core/src docs
  echo "fn a() {}" > hv-core/src/lib.rs
  echo "# doc" > docs/x.md
  git add -A && git commit -qm base
  echo "# doc, edited" > docs/x.md
  git add -A && git commit -qm docs-only
  echo "fn a() { let _ = 1; }" > hv-core/src/lib.rs
  git add -A && git commit -qm proof-relevant
) || { echo "FAIL — could not build the fixture repo"; exit 1; }

cd "$repo" || exit 1
BASE="$(git rev-parse HEAD~2)"
DOCS_ONLY="$(git rev-parse HEAD~1)"
PROOFY="$(git rev-parse HEAD)"

echo "detect-proof-changes-test: 7 cases"

# ── The five uncertainties. Each MUST run the proofs. ───────────────────────────────────────────
check "base sha empty"        true  env EVENT=pull_request PR_BASE=""      PR_HEAD="$PROOFY"
check "base sha all-zero"     true  env EVENT=push PUSH_BASE=0000000000000000000000000000000000000000 PUSH_HEAD="$PROOFY"
check "base not in history"   true  env EVENT=pull_request PR_BASE=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef PR_HEAD="$PROOFY"
check "git diff fails"        true  env EVENT=pull_request PR_BASE="$BASE" PR_HEAD="not-a-rev"
# ★ ㉓'s defect: `grep` exits 2 on a malformed pattern, which the old `if`/`else` read as "no match".
check "PROOF_PATHS malformed" true  env EVENT=pull_request PR_BASE="$BASE" PR_HEAD="$DOCS_ONLY" PROOF_PATHS='^(hv-core/'

# ── The positive control: a real proof-path change must run. ────────────────────────────────────
check "proof path changed"    true  env EVENT=pull_request PR_BASE="$DOCS_ONLY" PR_HEAD="$PROOFY"

# ── ★★ THE NEGATIVE CONTROL: without this, `run=true` on line 1 passes everything above. ────────
check "docs-only skips"       false env EVENT=pull_request PR_BASE="$BASE" PR_HEAD="$DOCS_ONLY"

if [ "$failed" -ne 0 ]; then
  echo "detect-proof-changes-test: FAILED"
  exit 1
fi
echo "detect-proof-changes-test: OK — 7/7, fail-safes run and docs-only skips"
