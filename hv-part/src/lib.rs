// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) 2026 Via Balaena

// ⑳ — `forbid`, not `deny`: this crate is pure arithmetic and has never needed `unsafe`, and a
// convention is not a gate. `hv-metal` is deliberately NOT given this — it is the fenced layer.
#![forbid(unsafe_code)]
#![no_std]

//! # The partition — which slot owns what
//!
//! `hv-metal` splits one machine among guest slots: each slot gets a run of model frames, a run of
//! `L2` page tables, an IPA window, a domain id, and a set of vCPU affinities. **Every one of those
//! is `slot`-indexed arithmetic, and every one of them is a place where an off-by-one crosses a
//! domain boundary** — the exact failure the whole isolation thesis exists to exclude.
//!
//! ## Why this is a crate and not four `const fn`s in `hv-metal`
//!
//! It *was* four `const fn`s in `hv-metal`, and they were guarded — by `const assert!`s evaluated at
//! **the sizes the board deploys**: two guests, two vCPUs. That is a check of two cases. `hv-metal`
//! is workspace-EXCLUDED (its bare-metal binary cannot link for the host), so nothing in it is
//! reachable by `hv-verify`, and no amount of care there turns two cases into all of them.
//!
//! Under the fence the same arithmetic is ∀-checkable. [`Partition`] carries the parameters, the
//! derivations are `const fn` so `hv-metal` keeps its compile-time guards unchanged, and the
//! properties below are proven in `hv-verify` for a **symbolic** partition rather than for the one
//! this board happens to have.
//!
//! ⚠ **What this crate is NOT.** It is not `hv_s2::arm64::Layout` (not linkable — this crate deliberately takes no dependencies), which describes ONE domain's
//! Stage-2 encoding — table PAs, granule, IPA bases. This is the level above: how the machine is
//! divided *between* domains, before any of them has an image. The two meet where `hv-metal` builds
//! a `Layout` per slot from a `Partition`.
//!
//! ⚠ **And it is not a claim about the hardware.** That each slot's window is disjoint from its
//! peer's is arithmetic; that the *hardware refuses* a guest reaching into its peer's is Stage-2's,
//! witnessed on the metal since ③-b2b-ii-d. This crate makes the first one total. It says nothing
//! about the second, and a partition that is perfectly disjoint on paper is worth nothing if the
//! emitter is handed the wrong one — which is why `hv-metal` derives EVERY slot-indexed address
//! from here rather than keeping a second opinion.

/// A domain id. Mirrors `hv_core::hypervisor::DomId` (a `u16`) without depending on it — see the
/// crate's `Cargo.toml` for why this crate takes no dependencies. `hv-metal` returns this straight
/// out of [`Partition::dom_of`], so a width disagreement is a compile error there, not a silent
/// truncation here.
pub type DomId = u16;

/// The privileged domain. Slot 0 is **not** `DOM0`: guests are numbered from 1, so that a slot
/// index and a domain id can never be confused by being accidentally equal.
pub const DOM0: DomId = 0;

/// **The one place `frames_per_guest * frame_bytes` is multiplied** — see
/// [`Partition::window_len`] for why the product is a definition rather than a theorem.
///
/// A free function taking two arguments rather than an eight-argument constructor: `Partition`'s
/// fields are all `u64`, so a positional constructor would let two of them be transposed with
/// everything still compiling — in a crate whose entire purpose is to prevent arithmetic mistakes.
/// Callers write a struct literal with named fields and call this for the one derived field.
#[must_use]
pub const fn window_len_from(frames_per_guest: u64, frame_bytes: u64) -> u64 {
    frames_per_guest * frame_bytes
}

/// How the machine is divided among guest slots.
///
/// All fields are counts or byte addresses; nothing here knows what a descriptor is. Construct one
/// and ask it questions — the derivations are the *only* place a slot becomes an address, so a
/// second opinion about where guest 2's RAM starts cannot exist (design-lesson #14c).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Partition {
    /// How many guest slots the machine is divided into.
    pub num_guests: u64,
    /// Super-span model frames each slot owns. Ownership of a disjoint run of these is what makes
    /// two domains disjoint **in the model**; the window arithmetic below merely follows it.
    pub frames_per_guest: u64,
    /// **Bytes of IPA one slot owns** — `frames_per_guest * frame_bytes`, carried as a field rather
    /// than recomputed.
    ///
    /// ⚠ **This shape was forced by MEASUREMENT, and it is the better decomposition anyway.** With
    /// the product recomputed inside every derivation, `window_base(slot)` was
    /// `ram_base + slot * frames_per_guest * frame_bytes` — a symbolic 64x64 multiply inside a
    /// per-slot loop, which CBMC bit-blasts in full regardless of any range assumption. The
    /// harnesses did not finish in 10 minutes. As a field it is `ram_base + slot * window_len`: ONE
    /// multiply by a slot index. **And the split is honest**: the isolation property is about
    /// ADDRESSES, while `frames x bytes` is how `hv-metal` computes the length — a definition, not a
    /// theorem, and proving it would be proving that multiplication is multiplication.
    /// [`window_len_from`] is the one place the product is taken.
    pub window_len: u64,
    /// IPA (and, on an identity-mapped board, PA) where slot 0's window begins.
    pub ram_base: u64,
    /// Exclusive end of the backed RAM window. No slot may extend past it.
    pub ram_end: u64,
    /// Total super-span frames backing the window — the base of the table partition sits here.
    pub num_sup_frames: u64,
    /// `L2` model tables each slot needs for its own leaves.
    pub tables_per_guest: u64,
    /// vCPUs each slot runs.
    pub vcpus_per_guest: u64,
}

impl Partition {
    /// **Whether this partition is one the derivations below are meaningful for.**
    ///
    /// Every property in this crate is stated *given* this. It is not a defensive check but the
    /// precondition: a partition with zero-byte frames or a window that does not fit has no
    /// disjointness to prove, and a proof that quantified over those too would be proving something
    /// about nonsense (and would fail, hiding the real property).
    ///
    /// `frames_per_guest * num_guests == num_sup_frames` is the **exact halving** `hv-metal`'s
    /// `const assert!` already demands: with a remainder, the top frames belong to nobody, and the
    /// disjointness walk — which infers ownership from the midpoint — would believe the last slot
    /// owns them.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        self.num_guests > 0
            // Every slot must have a domain id that fits, or `dom_of` truncates and two slots
            // silently share one — which is exactly what its injectivity proof would then be
            // asserting about a lie.
            && self.num_guests < DomId::MAX as u64
            && self.frames_per_guest > 0
            && self.window_len > 0
            && self.vcpus_per_guest > 0
            // No overflow anywhere below, checked as the precondition rather than saturated at each
            // use: a saturating derivation would silently alias two slots onto one address.
            // Written with `match` rather than `is_some_and` because the latter is not const-stable
            // at this workspace's MSRV, and these have to stay `const fn` for `hv-metal`'s
            // compile-time guards.
            && self.exact_halving()
            && self.window_fits()
            && self.tables_fit()
    }

    /// `num_guests * frames_per_guest == num_sup_frames`, without overflowing.
    const fn exact_halving(&self) -> bool {
        match self.num_guests.checked_mul(self.frames_per_guest) {
            Some(f) => f == self.num_sup_frames,
            None => false,
        }
    }

    /// Every slot's window fits between `ram_base` and `ram_end`, without overflowing.
    const fn window_fits(&self) -> bool {
        let span = match self.num_guests.checked_mul(self.window_len) {
            Some(s) => s,
            None => return false,
        };
        match self.ram_base.checked_add(span) {
            Some(end) => end <= self.ram_end,
            None => false,
        }
    }

    /// The table partition sits above the super partition without overflowing.
    const fn tables_fit(&self) -> bool {
        let t = match self.num_guests.checked_mul(self.tables_per_guest) {
            Some(t) => t,
            None => return false,
        };
        self.num_sup_frames.checked_add(t).is_some()
    }

    /// Whether `slot` is a slot this partition has.
    #[must_use]
    pub const fn has_slot(&self, slot: u64) -> bool {
        slot < self.num_guests
    }

    /// The first super-span model frame `slot` owns.
    #[must_use]
    pub const fn first_frame(&self, slot: u64) -> u64 {
        slot * self.frames_per_guest
    }

    /// One past the last super-span frame `slot` owns.
    #[must_use]
    pub const fn frames_end(&self, slot: u64) -> u64 {
        self.first_frame(slot) + self.frames_per_guest
    }

    /// The first `L2` model table `slot` owns — just above the super partition, in the base
    /// partition, and never mapped (a page table is model state, not a leaf).
    #[must_use]
    pub const fn first_table(&self, slot: u64) -> u64 {
        self.num_sup_frames + slot * self.tables_per_guest
    }

    /// One past the last `L2` model table `slot` owns.
    #[must_use]
    pub const fn tables_end(&self, slot: u64) -> u64 {
        self.first_table(slot) + self.tables_per_guest
    }

    /// The IPA where `slot`'s window begins.
    ///
    /// Equal to `ram_base + first_frame(slot) * frame_bytes` — the form `hv-metal` used to write —
    /// because `first_frame(slot) * frame_bytes == slot * frames_per_guest * frame_bytes ==
    /// slot * window_len`. See [`Partition::window_len`] for why it is expressed this way.
    #[must_use]
    pub const fn window_base(&self, slot: u64) -> u64 {
        self.ram_base + slot * self.window_len
    }

    /// Exclusive end of `slot`'s window.
    #[must_use]
    pub const fn window_end(&self, slot: u64) -> u64 {
        self.window_base(slot) + self.window_len
    }

    /// Whether `ipa` falls inside `slot`'s own window.
    #[must_use]
    pub const fn window_contains(&self, slot: u64, ipa: u64) -> bool {
        self.window_base(slot) <= ipa && ipa < self.window_end(slot)
    }

    /// Which slot's window contains `ipa`, if any.
    ///
    /// The inverse of [`window_base`](Self::window_base), and proven to be exactly that: the
    /// biconditional `owner_of(ipa) == Some(s) ⟺ window_contains(s, ipa)` is what makes "this
    /// address belongs to the peer" a decidable question rather than a comparison someone wrote out
    /// by hand at the fault site.
    #[must_use]
    pub const fn owner_of(&self, ipa: u64) -> Option<u64> {
        let mut slot = 0;
        while slot < self.num_guests {
            if self.window_contains(slot, ipa) {
                return Some(slot);
            }
            slot += 1;
        }
        None
    }

    /// The domain id `slot` runs as. **Never [`DOM0`]**, and injective in `slot`.
    #[must_use]
    pub const fn dom_of(&self, slot: u64) -> DomId {
        slot as DomId + 1
    }

    /// An address `offset` bytes into `slot`'s window — the one derivation of where a blob lands.
    ///
    /// Returns `None` when the offset would leave the window, which is the check `hv-metal`'s
    /// per-blob `const assert!`s make one at a time for the offsets this board happens to use.
    #[must_use]
    pub const fn in_window(&self, slot: u64, offset: u64) -> Option<u64> {
        if !self.has_slot(slot) || offset >= self.window_len {
            return None;
        }
        Some(self.window_base(slot) + offset)
    }

    /// The top `len` bytes of `slot`'s window — where a reserved range (⑲-3a's DMA landing pad)
    /// goes, because it is the one place whose address is a function of the partition alone.
    #[must_use]
    pub const fn window_top(&self, slot: u64, len: u64) -> Option<u64> {
        if !self.has_slot(slot) || len == 0 || len > self.window_len {
            return None;
        }
        Some(self.window_end(slot) - len)
    }

    /// Whether every slot's window lies inside the backed RAM.
    #[must_use]
    pub const fn windows_in_range(&self) -> bool {
        let mut slot = 0;
        while slot < self.num_guests {
            if self.window_end(slot) > self.ram_end {
                return false;
            }
            slot += 1;
        }
        true
    }

    /// **Whether no two slots' windows overlap** — the arithmetic half of the isolation thesis.
    #[must_use]
    pub const fn windows_disjoint(&self) -> bool {
        let mut a = 0;
        while a < self.num_guests {
            let mut b = a + 1;
            while b < self.num_guests {
                if self.window_base(a) < self.window_end(b)
                    && self.window_base(b) < self.window_end(a)
                {
                    return false;
                }
                b += 1;
            }
            a += 1;
        }
        true
    }

    /// Whether no two slots share a model frame, and no slot's frames collide with any slot's
    /// tables. Frames and tables live in one model index space, so "the table partition starts
    /// above the super partition" is an arithmetic claim, not a naming convention.
    #[must_use]
    pub const fn frames_disjoint(&self) -> bool {
        let mut a = 0;
        while a < self.num_guests {
            if self.first_table(a) < self.num_sup_frames {
                return false;
            }
            let mut b = a + 1;
            while b < self.num_guests {
                if self.first_frame(a) < self.frames_end(b)
                    && self.first_frame(b) < self.frames_end(a)
                {
                    return false;
                }
                if self.first_table(a) < self.tables_end(b)
                    && self.first_table(b) < self.tables_end(a)
                {
                    return false;
                }
                b += 1;
            }
            a += 1;
        }
        true
    }
}
