<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `hv-fuzz` — coverage-guided fuzzing against the proven core

`cargo-fuzz` targets against [`hv-core`](../hv-core/README.md)'s pure seams. Because the core is a
`no_std` library with **no VM in the loop**, these run natively at millions of exec/sec — the same
property that makes `hv-sim` fast makes fuzzing cheap.

## Where it sits

**Standalone** (its own empty `[workspace]`) and **excluded** from the parent workspace, so stable
`cargo test --workspace` never pulls in nightly or libFuzzer.

★ **Every target's contract is mirrored as a deterministic test on stable**, so CI proves the property
even though CI never runs the fuzzer. That is the load-bearing design decision here: the fuzzer finds
*new* inputs, the mirror keeps the property *gated*. CI additionally builds every target
(`fuzz targets build`, a required check) so a target cannot rot into non-compilation unnoticed.

## Running it

⚠ **This is a FLATTENED cargo-fuzz project — there is no `hv-fuzz/fuzz/` directory** — so it must be
driven with `--fuzz-dir` **from the repo root**:

```sh
cargo install cargo-fuzz                                   # once, needs nightly

cargo +nightly fuzz list --fuzz-dir hv-fuzz                # the targets
cargo +nightly fuzz run  --fuzz-dir hv-fuzz decode         # fuzz one
```

⛔ **`cd hv-fuzz && cargo +nightly fuzz run decode` does NOT work**, and this file told readers to do
exactly that until 2026-08-09. Bare `cargo fuzz` looks for `./fuzz/` and fails with a message about a
missing project rather than about the layout — so the failure reads as "this repo is broken" instead
of "use `--fuzz-dir`". A dead command costs more than a dead link: it fails in the reader's hands at
the moment they are checking a claim.

## Targets

⚠ **Gated** (`cargo xtask doc-modules`): every file in `fuzz_targets/` appears below exactly once.
This table listed **4 of 7** until 2026-08-09 — `p2m`, `policy` and `sched` had been invisible since
they were added, and a table that reads as complete is how a corpus goes unmaintained.

| target | seam under test | mirror test on stable |
| --- | --- | --- |
| [`decode`](fuzz_targets/decode.rs) | `hv_core::Hypercall::decode` — the ABI decode seam | `hv-core/src/lib.rs` — `decode_contract_holds_*` |
| [`evtchn`](fuzz_targets/evtchn.rs) | `hv_core::evtchn::System` — the event-channel machine | `hv-sim/src/scenario.rs` — `evtchn_invariants_hold_across_many_seeds` |
| [`grant`](fuzz_targets/grant.rs) | `hv_core::grant::System` — the grant-table machine | `hv-sim/src/scenario.rs` — `grant_invariants_hold_across_many_seeds` |
| [`p2m`](fuzz_targets/p2m.rs) | `hv_core::p2m::System` — page-type accounting and the page-table hierarchy | `hv-sim/src/scenario.rs` — `p2m_invariants_hold_across_many_seeds` |
| [`policy`](fuzz_targets/policy.rs) | `hv_core::policy::Scheduler` — the layer that *picks*, above the scheduler | `hv-sim/src/scenario.rs` — `policy_is_consistent_and_work_conserving_across_seeds` |
| [`sched`](fuzz_targets/sched.rs) | `hv_core::sched::System` — the scheduler state machine | `hv-sim/src/scenario.rs` — `sched_invariants_hold_across_many_seeds` |
| [`hypervisor`](fuzz_targets/hypervisor.rs) | `hv_core::Hypervisor` — the integrated dispatch seam | `hv-sim/src/scenario.rs` — `hypervisor_invariants_hold_across_many_seeds` |

## `artifacts/` is empty, and that is the point

A crash artifact here is a **real signal**, not a leftover. The one that ever appeared — a false
positive from #124 — was re-run, did not reproduce, and was deleted rather than kept as scenery.

⚠ **Measure it with `find artifacts -type f`, never `ls artifacts`.** cargo-fuzz creates one empty
**directory per target**, so `ls | wc -l` reads **7** on a perfectly clean tree — indistinguishable
from seven crashes, against a rule that says any file here matters.

## Where fuzzing sits among the four methods

Fuzzing is the *least* conclusive of the evidence this project carries, and it is kept because it is
the only one that is genuinely adversarial about **input shape**:

| method | what it establishes |
|---|---|
| property tests + seeded scenarios | the invariants hold on the paths we thought of |
| **fuzzing (here)** | ...and on input shapes nobody thought of |
| exhaustive sweeps (`cargo xtask sweeps`) | every reachable state of a bounded configuration |
| Kani + Verus ([`hv-verify`](../hv-verify/README.md)) | every state, bounded and then ∀-N |

A fuzz finding is a bug. **A clean fuzz run is not a proof** — that is what the other three rows are
for.

## The reference

```
cargo doc -p hv-core --open      # the seams these targets drive
```
