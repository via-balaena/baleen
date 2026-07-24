// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

#![no_std]

//! # `hv-s2` — Stage-2 emission, factored out of the `unsafe` metal
//!
//! The isolation-critical decision of the whole metal build is a single question: **which machine
//! frames does a domain's hardware page table reach, and at what permission?** Until now that
//! decision lived inside `hv-metal`'s `unsafe` — fused with the raw descriptor writes — so it could
//! only be argued (Architecture Audit #2) and mutation-tested, never *checked over every reachable
//! state* nor proven. This crate is that decision, extracted: a pure, `no_std`, zero-`unsafe`
//! library under the workspace fence, so it is host-testable, fuzzable, enumerable, and (next arc)
//! provable — while `hv-metal` keeps only the nub that publishes the result to hardware.
//!
//! ## The two layers, and why the seam is there
//!
//! - [`leafmap`] — **architecture-neutral.** The refinement content: the proven `p2m` relation →
//!   a per-frame leaf map (`Mfn → Option<Perm>`). The isolation claim is about *reachability and
//!   permission*, which has nothing to do with descriptor bits, so this layer is where the theorem
//!   lives — and proving it once serves an x86 EPT backend as well as AArch64 Stage-2 (ARM stays
//!   co-equal, and `hv-hal` stays neutral — the standing constraint).
//! - [`arm64`] — **AArch64-specific.** The bit-format: leaf map → Stage-2 descriptor values,
//!   written into caller-provided table storage. Pure — it touches no hardware and performs no
//!   MMIO; publishing (the barriers and TLB maintenance) stays in `hv-metal`.
//!
//! ## The refinement this crate is the subject of
//!
//! > Stage-2(G) maps IPA(m) → PA(m) at permission π **⟺** m is a leaf child of a page table G
//! > owns, at permission π.
//!
//! That biconditional is the load-bearing claim of the metal build. It was prose; the point of this
//! crate is to make it a *checkable* — and then provable — property of a function. See
//! `docs/AUDIT-2-P2M-STAGE2.md` for the argument this replaces, and the module docs below.
//!
//! ## What is verified, arrow by arrow — and what is NOT
//!
//! The metal's isolation rests on a chain, and the honest thing is to say how strong each link is
//! *separately*, because a claim about the whole chain is only as good as its weakest arrow:
//!
//! ```text
//!     p2m model  --(1)-->  leaf map  --(2)-->  descriptor words  --(3)-->  hardware
//! ```
//!
//! 1. **model → leaf map** ([`leafmap`]). Checked by `hv-sim`'s enumerator at **every reachable
//!    state** of its configs (828,325 states on the deep grant↔p2m sweep) and by `hv-fuzz` after
//!    every dispatch, via [`check`]. The properties are stated there, including which of them is a
//!    genuine theorem and which is only a consistency check. The theorem —
//!    [`check::check_authorized`], *no reachability without authorization* — is now **proven ∀-N**:
//!    over an arbitrary edge population in Verus
//!    (`hv-verify/verus/stage2_leaf_authorized.rs`), and on the **shipped**
//!    [`leafmap::leaf_map_from_edges`] by Kani over every ownership assignment, grant table,
//!    permission and capacity at bounded edge count (`hv-verify::stage2_refinement`). Its premise —
//!    hv-core's `UnauthorizedForeignLink` — is **also** proven ∀-N (preservation over every
//!    transition class, `hv-verify/verus/foreign_link_preservation.rs`), and the allocated-child
//!    premise falls out of the standing `MislevelledLink` invariant. See
//!    `docs/STAGE2-REFINEMENT-FORALL-N.md` for the theorem and the remaining ledger.
//!    Note this is **soundness, not completeness**: see the interior-node bullet below.
//! 2. **leaf map → descriptor words** ([`arm64`]). [`arm64::verify_encoding`] reads the emitted
//!    tables back and asserts they mean exactly the leaf map and *nothing else* (no spurious live
//!    slot anywhere in any table); the metal runs it on the real tables under `--features selftest`
//!    on every CI boot. The bit-level encoding itself is **proven** by Kani over all 2⁶⁴ output
//!    addresses (`hv-verify::stage2_encoding`): round-trip, always-execute-never data leaves, no
//!    RO→RW escalation, and the guest image always read-only + executable.
//! 3. **descriptors → hardware** — QEMU/TCG, exercised by the boot-test's isolation matrix
//!    (including the exact `DFSC=0x07` translation vs `0x0F` permission fault-class
//!    discriminators). Faithful for CPU-initiated Stage-2 accesses; blind to timing, weak-memory
//!    ordering, and DMA/SMMU (`docs/QEMU-AND-METAL.md`).
//!
//! ### Scope boundaries the claim does NOT cover (state these before proving anything)
//!
//! - **Interior-node sharing.** The model permits a domain to share a whole page-table *subtree*
//!   (a foreign `L(k-1)` node). The emitter maps only **leaves of tables the domain owns**, so a
//!   domain holding a legitimately shared subtree gets **no** mapping for the leaves beneath it.
//!   That is an *under*-map: it fails **closed** (the guest faults where the model would allow),
//!   never open. The refinement claim is therefore about **leaf-level frame reachability**, not
//!   full model reachability — and any theorem must say so or it is simply false.
//! - **Superpage size.** A model leaf pins exactly one `Mfn` (contiguity of a 2 MiB/1 GiB
//!   superpage's sub-frames is abstracted out as an hv-metal concern), and the emitter maps it as
//!   one 4 KiB page. Expanding a real superpage is unmodelled here.
//! - **The guest-image block is infrastructure, not model-driven.** It is identity-mapped from the
//!   linker window and is the **one mapping two domains hold in common** (M5 Arc 2 maps the same
//!   host frames into both). [`leaf_map`] says nothing about it. Its safety is instead pinned
//!   structurally: read-only so it cannot be a cross-domain *write* channel, executable so the
//!   guest can fetch, and its window disjoint from the data window
//!   ([`arm64::Layout::validate`]) — all checked, and the RO+X part proven by Kani. It remains a
//!   shared *read* surface by construction; that is a deliberate design choice, not an oversight.
//! - **`GuestMem` is the trusted path.** The hypervisor's own reads/writes of guest memory are
//!   deliberately unconditional on `S2AP` — permission enforcement is Stage-2's job for the
//!   *guest*, not for the core's own accesses.
//! - **VMID / table-set binding.** That domain → table set → `VMID` is injective lives in
//!   `hv-metal`, not here, and is not covered by these properties.
//!
//! ## Zero unsafe
//!
//! Inherits the workspace `unsafe_code = "forbid"` fence. Every function here is total and pure:
//! it reads a `&System` and writes caller-owned slices. Nothing dereferences a raw pointer, and
//! nothing here can fault.

pub mod arm64;
pub mod check;
pub mod leafmap;

pub use check::{
    check_all, check_authorized, check_authorized_with, OutOfDomain, Verdict, Violation,
};
pub use leafmap::{
    leaf_map, leaf_map_from_edges, span_of_table, Edge, FrameOutOfRange, MapError, Maps, Perm, Span,
};
