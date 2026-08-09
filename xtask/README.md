<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# `xtask` — the task runner, and where every gate lives

```
cargo xtask <task>
```

★ **This is not glue.** Every corpus this project pins, and every check standing between a claim in
prose and the code, is a function in `src/main.rs`. If you want to know what Baleen actually
enforces, read this crate.

## The one command that matters

```
cargo xtask ci      # fmt · clippy · test · doc · the doc gates · the sweeps
```

**Run it before every push.** It is the real entry point — the CI workflow calls the same tasks.

⚠ `verus-counts` and `kani-harnesses` are **separate** gates (different toolchains; Kani takes
~14 minutes), and `metal-lint` / `fvp-lint` build the excluded crates. `ci` does not run those.

## The gate corpora

Six bodies of evidence, each pinned by name or count, each with a **universe check** — an
enumeration of the covered set made *independently* of the table that claims to cover it:

| task | what it pins |
|---|---|
| `kani-harnesses` | the Kani corpus, by name |
| `verus-counts` | the Verus obligations, by count |
| `sweeps` | the exhaustive enumerators, by name |
| `doc-markers` | the boot markers the metal gate asserts, by per-array count |
| `doc-counts` | the README's stated corpus counts and the proof-to-code ratio |
| `doc-paths` · `doc-index` | every path the docs cite resolves; the docs index is complete |

## Metal and instruments

```
cargo xtask qemu-test          # the hypervisor boots, under QEMU
cargo xtask qemu-linux-test    # a real Alpine kernel boots behind the proven emitter
cargo xtask metal-lint         # hv-metal: fmt, clippy, rustdoc, across every feature config
cargo xtask fvp-lint           # the standalone probes (fvp-probe, board-probe)
```

⚠ `qemu-linux-test` needs the guest image first: `hv-metal/linux/fetch-guest-image.sh`.

## The reference

```
cargo doc -p xtask --open
```
