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
//! ## Zero unsafe
//!
//! Inherits the workspace `unsafe_code = "forbid"` fence. Every function here is total and pure:
//! it reads a `&System` and writes caller-owned slices. Nothing dereferences a raw pointer, and
//! nothing here can fault.

pub mod arm64;
pub mod leafmap;

pub use leafmap::{leaf_map, FrameOutOfRange, Perm};
