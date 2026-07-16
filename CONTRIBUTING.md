<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->
<!-- Copyright (c) 2026 Via Balaena -->

# Contributing to Baleen

Baleen is a type-1 hypervisor built brain-first: nearly all logic is host-testable
`no_std` Rust behind a hardware fence. Before changing anything, skim the
[README](README.md) architecture section so the layering is clear.

## The one bar: `cargo xtask ci`

Everything CI enforces, you can run locally:

```sh
cargo xtask ci      # rustfmt --check · clippy -D warnings · test · doc -D warnings
cargo xtask test    # just the tests
cargo xtask doc     # just the doc build (broken intra-doc links fail)
```

A change is ready when `cargo xtask ci` is green. CI runs the identical command, so
there are no surprises between your laptop and the remote.

## Architectural rules (enforced, not aspirational)

These are what keep the project testable and auditable. A change that breaks one
should change the design, not the rule:

1. **The fence holds.** `hv-core` reaches the outside world *only* through the
   `hv-hal` traits — never hardware directly. `unsafe_code = "forbid"` is set
   workspace-wide; when `hv-metal` lands, it — and only it — overrides that, and its
   `unsafe` stays as small and fenced as possible.
2. **The core is ABI-neutral.** `hv-core` speaks operations (`HvCall`), not wire
   formats. Hypercall numbering, struct layouts, and boot protocols belong in a
   *personality* (`baleen-xenabi`, M5), never in the core.
3. **Every state-machine transition upholds its invariants.** New logic in a
   subsystem means: extend `first_violation()` with the property that must hold,
   check it on every transition (`debug_assert!`, free in release), and add both a
   deterministic seeded run in `hv-sim` and — where there's a pure seam — a
   `hv-fuzz` target. A rejected operation must be a true no-op: validate before you
   mutate.
4. **Logic is host-tested.** If it can be tested in `hv-sim` on the host, it must
   be. Hardware is for the thin translation layer only.

## Clean-room discipline

Baleen implements Xen's ABI **as a specification**, without deriving from Xen's GPL
source. This rule is live now — read [CLEANROOM.md](CLEANROOM.md) before consulting
any Xen reference, and add a `Provenance:` trailer to commits where Xen behavior
informed the design.

## Fuzzing

Fuzz targets live in `hv-fuzz` (a standalone crate, excluded from the workspace).
They need nightly and `cargo-fuzz`:

```sh
cargo install cargo-fuzz
cd hv-fuzz && cargo +nightly fuzz run <target>   # decode · evtchn · grant · hypervisor
```

Each target's property is mirrored as a deterministic test (in `hv-core` or
`hv-sim`), so CI proves it without running the fuzzer; the fuzzer explores wider.

## Commits

Keep commits focused and their messages explanatory — say *why*, not just *what*.
Licensing is dual Apache-2.0 / MIT; by contributing you agree your work is provided
under both.
