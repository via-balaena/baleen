// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

//! PR-gate BREAK-PATH probe — this file MUST FAIL Verus verification. It exists only to prove the
//! `verus proofs (PR)` gate has teeth (a proof-breaking PR goes red and cannot merge). Not merged.

use vstd::prelude::*;

verus! {

proof fn gate_break_probe() {
    assert(false);  // deliberately unprovable: the verus (PR) job must report FAILURE on this PR.
}

}
